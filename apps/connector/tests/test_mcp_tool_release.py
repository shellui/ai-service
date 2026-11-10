"""Release contract for every tool ``POST /c/<company_id>/mcp`` returns.

Upstream OpenAPI documents are pinned under ``fixtures/openapi/`` (identity, storage,
hosting, and email ``develop`` at the revisions named below). Downstream ``tools/list``
is what shellui-django 0.5.1 actually serves: ``_meta`` removed. The gateway is called
through the Django MCP endpoint with a company-scoped agent token. Upstream HTTP is
mocked at ``requests.post``.

Pinned revisions:
- identity-service c38b4141dfa344d74bc7854bf351df83fcbd9088
- storage-service 3da5cda21a48f9c16ca1af5bc5bd8daf71d2cdc3
- hosting-service 3e4721a17ec8821c527a61d616b59b99e7805475
- email-service f5b2cdfd5430d25dfa4140de32356b621adc521a

saas-service is not published; the gateway exposes no saas tools.

Regenerate ``fixtures/mcp_tool_release_snapshot.json`` only when the contract is
intentionally changed: ``UPDATE_MCP_TOOL_SNAPSHOT=1``.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import Mock, patch

import jwt
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from shellui_django.mcp.openapi_mcp import tool_access_flags
from shellui_django.mcp.openapi_tools import tools_from_schema as shellui_tools_from_schema
from shellui_django.mcp.routing import path_parameter_names
from shellui_django.mcp.write_gate import decide_write

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from apps.authapi.jwks_client import JWKSClient
from apps.connector.mcp_approval_gate import tool_traits_from_export
from apps.connector.mcp_approvals import ConsumeResult
from apps.connector.mcp_tenant import is_tenant_field
from apps.connector.mcp_tool_naming import resolve_mcp_tool_name, select_newest_api_version_operations
from apps.connector.mcp_tool_schema import (
    DESTRUCTIVE_POST_OPERATION_IDS,
    READ_ONLY_POST_OPERATION_IDS,
    openapi_schema_to_json_schema,
)
from apps.connector.mcp_views import _get_server

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))

FIXTURE_DIR = Path(__file__).resolve().parent / 'fixtures'
OPENAPI_DIR = FIXTURE_DIR / 'openapi'
SNAPSHOT_PATH = FIXTURE_DIR / 'mcp_tool_release_snapshot.json'
MCP_ACCEPT = 'application/json, text/event-stream'
COMPANY_LABEL = 'Acme'
SERVICES = ('identity', 'storage', 'hosting', 'email')

_PRIVATE_PEM_SENTINEL = _SIGNING


def _load_openapi(service: str) -> dict:
    return json.loads((OPENAPI_DIR / f'{service}.json').read_text(encoding='utf-8'))


def _wire_tools(schema: dict) -> list[dict]:
    """Tools exactly as shellui ``McpServer`` puts them on the wire (no ``_meta``)."""
    return [{k: v for k, v in tool.items() if not str(k).startswith('_')} for tool in shellui_tools_from_schema(schema)]


def _body_required(operation: dict, schema: dict) -> list[str]:
    body = operation.get('requestBody') or {}
    content = (body.get('content') or {}) if isinstance(body, dict) else {}
    raw = (content.get('application/json') or {}).get('schema') or {}
    if not isinstance(raw, dict) or not raw:
        return []
    resolved = openapi_schema_to_json_schema(raw, schema)
    props = resolved.get('properties') if isinstance(resolved.get('properties'), dict) else {}
    return [str(key) for key in (resolved.get('required') or []) if str(key) in props and not is_tenant_field(str(key))]


def _query_required(operation: dict) -> list[str]:
    required: list[str] = []
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('in') != 'query' or not param.get('required'):
            continue
        name = str(param.get('name') or '')
        if name and not is_tenant_field(name):
            required.append(name)
    return required


def _operations_by_route(schema: dict) -> dict[tuple[str, str], dict]:
    return {
        (path, method.upper()): operation
        for path, method, operation in select_newest_api_version_operations(schema)
    }


def _rpc(method: str, **params) -> str:
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


def _agent_token() -> str:
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': 'agent:agent-release',
        'agent_id': 'agent-release',
        'company_id': 10,
        'company_name': COMPANY_LABEL,
        'scope': 'ai identity storage hosting email',
        'mcp_access': 'full',
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'aud': 'https://ai.test/c/10/mcp',
        'iss': 'https://identity.test',
        'iat': now,
        'exp': now + 3600,
    }
    return jwt.encode(claims, 'test-hs256-secret-for-mcp-gateway-tests-only', algorithm='HS256')


def _sample(schema: dict, name: str) -> object:
    if not isinstance(schema, dict):
        return 'example'
    if 'const' in schema:
        return schema['const']
    enum = schema.get('enum')
    if isinstance(enum, list) and enum:
        for value in enum:
            if value is not None:
                return value
    typ = schema.get('type')
    if isinstance(typ, list):
        typ = next((item for item in typ if item != 'null'), 'string')
    if typ == 'integer':
        minimum = schema.get('minimum')
        return int(minimum) if isinstance(minimum, int) else 1
    if typ == 'number':
        return 1
    if typ == 'boolean':
        return True
    if typ == 'array':
        items = schema.get('items') if isinstance(schema.get('items'), dict) else {'type': 'string'}
        count = schema.get('minItems') if isinstance(schema.get('minItems'), int) else 0
        return [_sample(items, name) for _ in range(count)]
    if typ == 'object':
        props = schema.get('properties') if isinstance(schema.get('properties'), dict) else {}
        required = [str(key) for key in (schema.get('required') or []) if str(key) in props]
        keys = required or []
        return {key: _sample(props[key], key) for key in keys}
    if schema.get('format') == 'uuid' or name.endswith('_id') or name == 'id':
        return '11111111-1111-4111-8111-111111111111'
    if 'email' in name:
        return 'user@example.com'
    if schema.get('format') in {'uri', 'url'} or name.endswith('_url'):
        return 'https://example.com/resource'
    return 'example'


def _call_arguments(tool: dict) -> dict:
    props = (tool.get('inputSchema') or {}).get('properties') or {}
    arguments: dict = {}
    path = props.get('path') if isinstance(props.get('path'), dict) else {}
    method = props.get('method') if isinstance(props.get('method'), dict) else {}
    if 'const' in path:
        arguments['path'] = path['const']
    enum = method.get('enum')
    if isinstance(enum, list) and enum:
        arguments['method'] = enum[0]
    for section in ('path_params', 'query', 'body'):
        node = props.get(section)
        if not isinstance(node, dict):
            continue
        nested = node.get('properties') if isinstance(node.get('properties'), dict) else {}
        required = [str(key) for key in (node.get('required') or []) if str(key) in nested and not is_tenant_field(str(key))]
        if required:
            arguments[section] = {key: _sample(nested[key], key) for key in required}
    return arguments


def _client_contract(tool: dict, *, traits: tuple[bool, bool]) -> dict:
    read_only, destructive = traits
    decision = decide_write(
        method=str(((tool.get('inputSchema') or {}).get('properties') or {}).get('method', {}).get('enum', ['GET'])[0]),
        access_mode='ask',
        destructive=destructive,
        allow_destructive_without_asking=False,
        tool_read_only=read_only,
    )
    return {
        'name': tool.get('name'),
        'title': tool.get('title'),
        'description': tool.get('description'),
        'inputSchema': tool.get('inputSchema'),
        'annotations': tool.get('annotations'),
        'read_only': read_only,
        'destructive': destructive,
        'needs_approval': bool(decision.needs_approval),
    }


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_AUDIENCE='shellui-test',
    IDENTITY_JWKS_URL='http://localhost:8000/.well-known/jwks.json',
    IDENTITY_SERVICE_URL='https://identity.test',
    STORAGE_SERVICE_URL='https://storage.test',
    HOSTING_SERVICE_URL='https://hosting.test',
    EMAIL_SERVICE_URL='https://email.test',
    EMAIL_SERVICE_API_KEY='esk_test_gateway_route_cache',  # gitleaks:allow
    SAAS_SERVICE_URL='',
    AI_PUBLIC_URL='https://ai.test',
    AI_SERVICE_SIGNING_KEY=_PRIVATE_PEM_SENTINEL,
    AI_SERVICE_ISSUER='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS=3600,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-tool-release',
        }
    },
)
@patch('apps.authapi.agent_tokens.get_jwks_client', return_value=JWKSClient(static_document={'keys': []}))
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_approval_gate.agent_is_revoked', return_value=False)
class McpToolReleaseTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.schemas = {service: _load_openapi(service) for service in SERVICES}
        cls.wire = {service: _wire_tools(cls.schemas[service]) for service in SERVICES}
        cls.operations = {service: _operations_by_route(cls.schemas[service]) for service in SERVICES}

    def setUp(self):
        super().setUp()
        # Recreate the gateway so this test's cache TTL and service URLs apply.
        import apps.connector.mcp_views as mcp_views

        mcp_views._server = None
        cache.clear()
        self.client = Client()
        self.token = _agent_token()
        self.forwarded: list[dict] = []

    def _post(self, method: str, **params):
        # The 224-tool contract is the full catalog. The default list is discovery.
        path = '/c/10/mcp?tools=all' if method == 'tools/list' else '/c/10/mcp'
        return self.client.post(
            path,
            data=_rpc(method, **params),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
            HTTP_ACCEPT=MCP_ACCEPT,
        )

    def _install_upstream(self):
        wire_by_url = {
            'https://identity.test/mcp': self.wire['identity'],
            'https://storage.test/mcp': self.wire['storage'],
            'https://hosting.test/mcp': self.wire['hosting'],
            'https://email.test/mcp': self.wire['email'],
        }

        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') == 'tools/call':
                self.forwarded.append(
                    {
                        'url': url,
                        'name': (payload.get('params') or {}).get('name'),
                        'arguments': (payload.get('params') or {}).get('arguments') or {},
                    }
                )
                resp.json.return_value = {
                    'jsonrpc': '2.0',
                    'id': payload.get('id'),
                    'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': False},
                }
            else:
                tools = wire_by_url.get(str(url).split('?', 1)[0])
                resp.json.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {'tools': tools or []}}
            return resp

        return side_effect

    def _list_tools(self) -> list[dict]:
        tools: list[dict] = []
        cursor = None
        seen: set[str] = set()
        for _ in range(10):
            params = {'cursor': cursor} if cursor else {}
            response = self._post('tools/list', **params)
            self.assertEqual(response.status_code, 200, response.content[:500])
            body = response.json()
            self.assertNotIn('error', body, body)
            result = body['result']
            page = result['tools']
            self.assertTrue(page)
            for tool in page:
                name = tool['name']
                self.assertNotIn(name, seen)
                seen.add(name)
                tools.append(tool)
            cursor = result.get('nextCursor')
            if not cursor:
                break
        else:
            self.fail('tools/list pagination did not finish')
        # Search, describe, and call sit beside the operational catalog. The pinned
        # snapshot stays the 224 OpenAPI tools.
        from apps.connector.mcp_discovery import DISCOVERY_ONLY_TOOLS

        return [tool for tool in tools if tool['name'] not in DISCOVERY_ONLY_TOOLS]

    def _traits(self, name: str) -> tuple[bool, bool]:
        # The catalog cache is per company. This lookup runs after the HTTP request,
        # so the request claims context is gone.
        from apps.connector.mcp_views import _mcp_agent_claims

        token = _mcp_agent_claims.set({'company_id': 10})
        try:
            row = _get_server()._cached_export_tool(name)
        finally:
            _mcp_agent_claims.reset(token)
        self.assertIsInstance(row, dict, name)
        meta = row.get('_meta') if isinstance(row, dict) else {}
        return tool_traits_from_export(row, method=str((meta or {}).get('method') or 'GET'))

    def test_openapi_exceptions_match_recovered_access_sets(self, *_mocks):
        """A new read-only or destructive POST in the fixtures must be recovered explicitly."""
        read_only_posts: set[str] = set()
        destructive_posts: set[str] = set()
        for service in SERVICES:
            for path, method, operation in select_newest_api_version_operations(self.schemas[service]):
                flags = tool_access_flags(operation)
                if flags['read_only'] and method not in {'get', 'head', 'options'}:
                    read_only_posts.add(str(operation.get('operationId')))
                if flags['destructive'] and method != 'delete':
                    destructive_posts.add(str(operation.get('operationId')))
        self.assertEqual(read_only_posts, set(READ_ONLY_POST_OPERATION_IDS))
        self.assertEqual(destructive_posts, set(DESTRUCTIVE_POST_OPERATION_IDS))

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_views.requests.post')
    def test_tools_list_matches_openapi_and_snapshot(self, post, _mint, *_mocks):
        post.side_effect = self._install_upstream()
        listed = self._list_tools()
        self.assertEqual(len(listed), 224)
        self.assertGreater(len(listed), 200)
        by_name = {tool['name']: tool for tool in listed}
        self.assertEqual(len(by_name), len(listed))

        contracts = []
        seen_operations: set[tuple[str, str, str]] = set()
        for service in SERVICES:
            schema = self.schemas[service]
            wire_count = len(self.wire[service])
            selected = select_newest_api_version_operations(schema)
            self.assertEqual(
                wire_count,
                len(selected),
                f'{service} tools/list count drifted from the newest mcp-tools operations',
            )
            for path, method, operation in selected:
                flags = tool_access_flags(operation)
                local = resolve_mcp_tool_name(operation, method, path)
                export = f'{service}_{local}'
                self.assertIn(export, by_name, export)
                tool = by_name[export]
                props = tool['inputSchema']['properties']
                self.assertEqual(props['path']['const'], path, export)
                self.assertEqual(props['method']['enum'], [method.upper()], export)
                agent_path = [name for name in path_parameter_names(path) if not is_tenant_field(name)]
                if agent_path:
                    path_props = props['path_params']['properties']
                    self.assertEqual(sorted(path_props), sorted(agent_path), export)
                    self.assertEqual(props['path_params']['required'], agent_path, export)
                    self.assertIn('path_params', tool['inputSchema']['required'])
                else:
                    self.assertNotIn('path_params', props, export)
                query_props = (props.get('query') or {}).get('properties') or {}
                body_props = (props.get('body') or {}).get('properties') or {}
                self.assertNotIn('company_id', query_props, export)
                self.assertNotIn('companyId', query_props, export)
                self.assertNotIn('company_id', body_props, export)
                self.assertEqual(
                    sorted((props.get('query') or {}).get('required') or []),
                    sorted(_query_required(operation)),
                    export,
                )
                self.assertEqual(
                    sorted((props.get('body') or {}).get('required') or []),
                    sorted(_body_required(operation, schema)),
                    export,
                )
                read_only, destructive = self._traits(export)
                self.assertEqual(read_only, bool(flags['read_only']), export)
                self.assertEqual(destructive, bool(flags['destructive']), export)
                self.assertEqual(tool['annotations']['readOnlyHint'], read_only, export)
                self.assertEqual(tool['annotations']['destructiveHint'], destructive, export)
                self.assertTrue(tool['title'].startswith(_service_title(service)), tool['title'])
                self.assertIn(f'({COMPANY_LABEL})', tool['title'])
                self.assertNotIn('api_v', tool['name'])
                seen_operations.add((service, path, method.upper()))
                contracts.append(_client_contract(tool, traits=(read_only, destructive)))

        ai = by_name['ai_list_services']
        read_only, destructive = self._traits('ai_list_services')
        self.assertTrue(read_only)
        self.assertFalse(destructive)
        self.assertFalse(_client_contract(ai, traits=(read_only, destructive))['needs_approval'])
        contracts.append(_client_contract(ai, traits=(read_only, destructive)))
        self.assertEqual(len(seen_operations), 223)
        self.assertEqual({row['name'] for row in contracts}, set(by_name))

        contracts.sort(key=lambda row: row['name'])
        if os.environ.get('UPDATE_MCP_TOOL_SNAPSHOT') == '1':
            SNAPSHOT_PATH.write_text(
                json.dumps(contracts, sort_keys=True, separators=(',', ':')) + '\n',
                encoding='utf-8',
            )
            return
        pinned = json.loads(SNAPSHOT_PATH.read_text(encoding='utf-8'))
        self.assertEqual(contracts, pinned)

    @patch('apps.connector.mcp_approvals.approval_consume_detail', return_value=ConsumeResult(consumed=True, status_code=200))
    @patch('apps.connector.mcp_approvals.approval_state')
    @patch('apps.connector.mcp_views.forward_call_log')
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_views.requests.post')
    def test_each_tool_call_succeeds(self, post, _mint, _log, approval_state, _consume, *_mocks):
        def _approved(payload):
            payload['approval_id'] = 'appr-release'
            return 'approved'

        approval_state.side_effect = _approved
        post.side_effect = self._install_upstream()
        listed = self._list_tools()
        downstream_by_route: dict[tuple[str, str, str], str] = {}
        for service in SERVICES:
            for tool in shellui_tools_from_schema(self.schemas[service]):
                meta = tool.get('_meta') or {}
                downstream_by_route[(service, meta.get('path'), str(meta.get('method') or '').upper())] = tool['name']

        for tool in listed:
            name = tool['name']
            with self.subTest(tool=name):
                self.forwarded.clear()
                arguments = _call_arguments(tool)
                response = self._post('tools/call', name=name, arguments=arguments)
                self.assertEqual(response.status_code, 200, response.content[:800])
                body = response.json()
                self.assertNotIn('error', body, body)
                result = body.get('result') or {}
                self.assertFalse(result.get('isError'), result)
                if name == 'ai_list_services':
                    self.assertEqual(self.forwarded, [])
                    text = result['content'][0]['text']
                    self.assertIn('identity', text)
                    continue
                service = name.split('_', 1)[0]
                props = tool['inputSchema']['properties']
                path = props['path']['const']
                method = props['method']['enum'][0]
                self.assertEqual(len(self.forwarded), 1, self.forwarded)
                forwarded = self.forwarded[0]
                self.assertEqual(forwarded['url'], f'https://{service}.test/mcp')
                self.assertEqual(forwarded['name'], downstream_by_route[(service, path, method)])
                self.assertEqual(forwarded['arguments'].get('path'), path)
                self.assertEqual(forwarded['arguments'].get('method'), method)
                for section in ('path_params', 'query', 'body'):
                    expected = arguments.get(section) or {}
                    actual = forwarded['arguments'].get(section) or {}
                    for key, value in expected.items():
                        self.assertEqual(actual.get(key), value, f'{name} {section}.{key}')
                operation = self.operations[service][(path, method)]
                template_params = path_parameter_names(path)
                if any(is_tenant_field(param) for param in template_params):
                    self.assertEqual(str(forwarded['arguments']['path_params']['company_id']), '10', name)
                if any(
                    isinstance(param, dict) and param.get('in') == 'query' and is_tenant_field(str(param.get('name')))
                    for param in (operation.get('parameters') or [])
                ):
                    self.assertEqual(str(forwarded['arguments']['query']['company_id']), '10', name)

    @patch('apps.connector.mcp_approvals.approval_consume_detail', return_value=ConsumeResult(consumed=True, status_code=200))
    @patch('apps.connector.mcp_approvals.approval_state')
    @patch('apps.connector.mcp_views.forward_call_log')
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_views.requests.post')
    def test_each_service_accepts_published_upstream_names(self, post, _mint, _log, approval_state, _consume, *_mocks):
        """Upstream tools already named ``identity_create_groups`` publish the same catalog."""
        from apps.connector.mcp_tool_schema import normalize_mcp_tool
        from apps.connector.mcp_views import iter_gateway_remote_exports

        def _approved(payload):
            payload['approval_id'] = 'appr-release'
            return 'approved'

        approval_state.side_effect = _approved
        renamed: dict[str, list[dict]] = {}
        for service, tools in self.wire.items():
            exports = iter_gateway_remote_exports(
                [normalize_mcp_tool(dict(tool)) for tool in tools],
                service_id=service,
            )
            by_downstream = {route['downstream_name']: export_name for export_name, _tool, route in exports}
            self.assertEqual(len(by_downstream), len(tools), service)
            service_tools = []
            for tool in tools:
                copy = json.loads(json.dumps(tool))
                copy['name'] = by_downstream[tool['name']]
                service_tools.append(copy)
            renamed[service] = service_tools
        self.wire = renamed
        post.side_effect = self._install_upstream()
        listed = self._list_tools()
        contracts = []
        for tool in listed:
            if tool['name'] == 'ai_list_services':
                read_only, destructive = self._traits(tool['name'])
                contracts.append(_client_contract(tool, traits=(read_only, destructive)))
                continue
            read_only, destructive = self._traits(tool['name'])
            contracts.append(_client_contract(tool, traits=(read_only, destructive)))
        contracts.sort(key=lambda row: row['name'])
        pinned = json.loads(SNAPSHOT_PATH.read_text(encoding='utf-8'))
        self.assertEqual(contracts, pinned)

        for tool in listed:
            name = tool['name']
            with self.subTest(tool=name):
                self.forwarded.clear()
                response = self._post('tools/call', name=name, arguments=_call_arguments(tool))
                self.assertEqual(response.status_code, 200, response.content[:800])
                body = response.json()
                self.assertNotIn('error', body, body)
                self.assertFalse((body.get('result') or {}).get('isError'), body.get('result'))
                if name == 'ai_list_services':
                    continue
                self.assertEqual(len(self.forwarded), 1)
                self.assertEqual(self.forwarded[0]['name'], name)


def _service_title(service: str) -> str:
    return {
        'identity': 'Identity:',
        'storage': 'Storage:',
        'hosting': 'Hosting:',
        'email': 'Email:',
    }[service]
