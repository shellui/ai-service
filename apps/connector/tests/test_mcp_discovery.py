"""Discovery catalog: default tools/list, local search, and ai_call_tool parity."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import jwt
from django.core.cache import cache
from django.test import Client, SimpleTestCase, TestCase, override_settings

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from apps.connector.mcp_approvals import ConsumeResult
from apps.connector.mcp_tool_metadata_checks import validate_tools_list
from apps.connector.mcp_tool_presentation import apply_gateway_tool_presentation
from apps.connector.mcp_discovery import (
    DIRECT_READ_TOOLS,
    DISCOVERY_ONLY_TOOLS,
    discovery_tool_definitions,
    rank_tools,
    redact_arguments,
    search_payload,
)

FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'mcp_discovery_tools.json'
SNAPSHOT = Path(__file__).resolve().parent / 'fixtures' / 'mcp_tool_release_snapshot.json'

# Realistic agent phrasing. The first name is the tool the query is about.
GOLDEN_QUERIES: tuple[tuple[str, str], ...] = (
    ('invite a user', 'identity_create_invitations'),
    ('list users', 'identity_list_users'),
    ('who signed up last week', 'identity_list_events'),
    ('deploy my app', 'hosting_create_apps_deployments'),
    ('send a newsletter', 'email_create_newsletters'),
    ('make a file public', 'storage_create_share'),
    ('rotate webhook secret', 'email_rotate_rule_secret'),
    ('empty a bucket', 'storage_empty_bucket'),
    ('list buckets', 'storage_list_bucket'),
    ('list apps', 'hosting_list_apps'),
    ('list messages', 'email_list_messages'),
    ('create a group', 'identity_create_groups'),
    ('roll back a deployment', 'hosting_create_apps_deployments_rollback'),
    ('inviter un utilisateur', 'identity_create_invitations'),
    ('deployer mon application', 'hosting_create_apps_deployments'),
    ('envoyer une newsletter', 'email_create_newsletters'),
    ('rendre un fichier public', 'storage_create_share'),
    ("qui s'est inscrit", 'identity_list_events'),
    ('identity_list_users', 'identity_list_users'),
    ('identity_list_usres', 'identity_list_users'),
    ('deply my app', 'hosting_create_apps_deployments'),
    ('invite', 'identity_create_invitations'),
    ('newsletter', 'email_create_newsletters'),
    ('bucket', 'storage_list_bucket'),
    ('users', 'identity_list_users'),
    ('webhook signing secret', 'email_rotate_rule_secret'),
    ('sign a download', 'storage_sign_object'),
    ('delete a user', 'identity_delete_users'),
    ('revoke an invitation', 'identity_revoke_invitations'),
    ('create a hosted app', 'hosting_create_apps'),
    ('list domains', 'hosting_list_apps_domains'),
    ('preview a broadcast', 'email_broadcasts_preview'),
    ('export newsletter subscribers', 'email_export_newsletter_subscribers'),
    ('get company', 'identity_get_companies'),
    ('list events', 'identity_list_events'),
    ('rotate newsletter key', 'email_rotate_newsletter_key'),
    ('make a share link', 'storage_create_share'),
    ('upload a deployment', 'hosting_create_apps_deployments_artifact_upload_url'),
    ('list groups', 'identity_list_groups'),
    ('who is in the company', 'identity_list_users'),
    ('send a test email', 'email_send_test_templates'),
    ('public file link', 'storage_sign_object'),
    ('vider un bucket', 'storage_empty_bucket'),
    ('invitation', 'identity_create_invitations'),
    ("déployer l'application", 'hosting_create_apps_deployments'),
    ('fichier public', 'storage_create_share'),
    ('secret webhook', 'email_rotate_rule_secret'),
    ('hosting_list_apps', 'hosting_list_apps'),
    ('storage_list_bucket', 'storage_list_bucket'),
    ('email_create_newsletters', 'email_create_newsletters'),
)


class DiscoveryRankingTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.catalog = json.loads(SNAPSHOT.read_text(encoding='utf-8'))

    def test_discovery_tool_contract_is_pinned(self):
        pinned = json.loads(FIXTURE.read_text(encoding='utf-8'))
        current = json.loads(json.dumps(discovery_tool_definitions(), sort_keys=True))
        self.assertEqual(current, pinned)
        self.assertEqual({tool['name'] for tool in pinned}, set(DISCOVERY_ONLY_TOOLS))
        for tool in pinned:
            self.assertGreaterEqual(len(tool['description']), 24)
            self.assertNotIn('\u2014', tool['description'])
            self.assertIn('Shellui', tool['description'])
        presented = [
            apply_gateway_tool_presentation(tool, company_label='Acme') for tool in discovery_tool_definitions()
        ]
        self.assertEqual(validate_tools_list(presented), [])

    def test_golden_queries_rank_the_expected_tool(self):
        self.assertGreaterEqual(len(GOLDEN_QUERIES), 40)
        top1 = 0
        top3 = 0
        misses = []
        for query, expected in GOLDEN_QUERIES:
            names = [tool['name'] for _score, tool in rank_tools(self.catalog, query, limit=3)]
            if names and names[0] == expected:
                top1 += 1
            if expected in names:
                top3 += 1
            else:
                misses.append((query, expected, names))
        self.assertEqual(misses, [])
        self.assertEqual(top1, len(GOLDEN_QUERIES))
        self.assertEqual(top3, len(GOLDEN_QUERIES))

    def test_filters_limit_typos_and_empty_results(self):
        read_names = [
            tool['name']
            for _score, tool in rank_tools(self.catalog, 'user', access='read', limit=8)
        ]
        self.assertIn('identity_list_users', read_names)
        self.assertTrue(all(not name.startswith('identity_create_') for name in read_names))
        write_names = [
            tool['name']
            for _score, tool in rank_tools(self.catalog, 'invite a user', access='write', service='identity', limit=5)
        ]
        self.assertEqual(write_names[0], 'identity_create_invitations')
        self.assertTrue(all(name.startswith('identity_') for name in write_names))
        capped = rank_tools(self.catalog, 'list', limit=20)
        self.assertLessEqual(len(capped), 20)
        self.assertEqual(rank_tools(self.catalog, 'identity_list_usres', limit=1)[0][1]['name'], 'identity_list_users')
        payload = search_payload(self.catalog, {'query': 'zzzz-not-a-tool'}, access_mode='ask')
        self.assertEqual(payload['matches'], [])
        self.assertIn('ai_list_services', payload['hint'])
        self.assertEqual(redact_arguments({'api_key': 'sekret', 'name': 'Ada'})['api_key'], '***')


_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))
AI_MCP = 'https://ai.test/c/10/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'
_AGENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

STORAGE_TOOLS = {
    'jsonrpc': '2.0',
    'id': 1,
    'result': {
        'tools': [
            {
                'name': 'list_buckets',
                'description': 'List buckets',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'path': {'type': 'string', 'const': '/api/v1/buckets/'},
                        'method': {'type': 'string', 'enum': ['GET']},
                    },
                    'required': ['path', 'method'],
                    'additionalProperties': False,
                },
                '_meta': {'method': 'GET', 'path': '/api/v1/buckets/', 'read_only': True},
            },
            {
                'name': 'create_bucket',
                'description': 'Create a bucket',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'path': {'type': 'string', 'const': '/api/v1/buckets/'},
                        'method': {'type': 'string', 'enum': ['POST']},
                        'body': {
                            'type': 'object',
                            'properties': {'name': {'type': 'string'}, 'api_key': {'type': 'string'}},
                        },
                    },
                    'required': ['path', 'method'],
                    'additionalProperties': False,
                },
                'annotations': {
                    'readOnlyHint': False,
                    'destructiveHint': False,
                    'idempotentHint': False,
                    'openWorldHint': True,
                },
                '_meta': {'method': 'POST', 'path': '/api/v1/buckets/', 'read_only': False, 'destructive': False},
            },
            {
                'name': 'delete_bucket',
                'description': 'Delete a bucket',
                '_meta': {'method': 'DELETE', 'path': '/api/v1/buckets/{id}/', 'read_only': False, 'destructive': True},
            },
        ]
    },
}


def _rpc(method: str, **params) -> str:
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


def _token(
    *,
    secret: str,
    issuer: str,
    mcp_access: str = 'ask',
    scope: str = 'ai storage',
    company_id: int = 10,
) -> str:
    import time

    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': f'agent:{_AGENT}',
        'agent_id': _AGENT,
        'agent_name': 'Test Agent',
        'company_id': company_id,
        'company_name': 'Acme',
        'scope': scope,
        'mcp_access': mcp_access,
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'grant_version': 1,
        'aud': f'https://ai.test/c/{company_id}/mcp',
        'iss': issuer,
        'iat': now,
        'exp': now + 3600,
    }
    return jwt.encode(claims, secret, algorithm='HS256')


def _identity_http(url, **kwargs):
    resp = Mock()
    if str(url).rstrip('/').endswith('/mcp-agent-delegated-authority'):
        resp.status_code = 404
        return resp
    if str(url).rstrip('/').endswith('/mcp-call-logs'):
        resp.status_code = 204
        return resp
    raise AssertionError(url)


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',  # gitleaks:allow
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    STORAGE_SERVICE_URL='https://storage.test',
    AI_PUBLIC_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_TOOLS_LIST_MODE='discovery',
    MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=0,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'mcp-discovery'}},
)
@patch('apps.connector.mcp_approval_gate.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class DiscoveryGatewayTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.secret = 'test-hs256-secret-for-mcp-gateway-tests-only'  # gitleaks:allow
        self.issuer = 'https://identity.test'

    def _auth(self, token: str, *, session_id: str | None = None) -> dict:
        headers = {'HTTP_AUTHORIZATION': f'Bearer {token}', 'HTTP_ACCEPT': MCP_ACCEPT}
        if session_id:
            headers['HTTP_MCP_SESSION_ID'] = session_id
        return headers

    def _session(self, token: str) -> str:
        response = self.client.post(
            '/c/10/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'initialize',
                    'params': {'protocolVersion': '2025-06-18', 'capabilities': {'elicitation': {}}},
                }
            ),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        text = response.json()['result']['instructions']
        self.assertIn('ai_search_tools', text)
        self.assertIn('ai_call_tool', text)
        self.assertNotIn('\u2014', text)
        return response['Mcp-Session-Id']

    def _storage(self, post):
        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') == 'tools/call':
                resp.json.return_value = {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': False},
                }
            else:
                resp.json.return_value = STORAGE_TOOLS
            return resp

        post.side_effect = side_effect

    def _names(self, token: str, *, query: str = '') -> list[str]:
        response = self.client.post(
            f'/c/10/mcp{query}',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        return [tool['name'] for tool in response.json()['result']['tools']]

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_default_list_is_discovery_and_all_opts_in(self, post, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer)
        default = self._names(token)
        self.assertIn('ai_list_services', default)
        self.assertTrue(DISCOVERY_ONLY_TOOLS <= set(default))
        self.assertNotIn('storage_list_buckets', default)
        self.assertLess(len(default), 20)
        full = self._names(token, query='?tools=all')
        self.assertIn('storage_list_buckets', full)
        self.assertTrue(DISCOVERY_ONLY_TOOLS <= set(full))
        params = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list', tools='all'),
            content_type='application/json',
            **self._auth(token),
        )
        param_names = [tool['name'] for tool in params.json()['result']['tools']]
        self.assertIn('storage_list_buckets', param_names)

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_search_and_describe_return_schemas(self, post, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer)
        self._names(token)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_search_tools', arguments={'query': 'list buckets', 'limit': 3}),
            content_type='application/json',
            **self._auth(token),
        )
        body = json.loads(response.json()['result']['content'][0]['text'])
        self.assertFalse(response.json()['result']['isError'])
        self.assertEqual(body['matches'][0]['name'], 'storage_list_buckets')
        self.assertNotIn('inputSchema', body['matches'][0])
        self.assertNotIn('method', body['matches'][0])
        self.assertIn('read_only', body['matches'][0])
        self.assertIn('needs_approval', body['matches'][0])
        self.assertLessEqual(len(json.dumps(body)), 4000)
        described = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_describe_tool', arguments={'name': 'storage_list_buckets'}),
            content_type='application/json',
            **self._auth(token),
        )
        detail = json.loads(described.json()['result']['content'][0]['text'])
        self.assertEqual(detail['tools'][0]['name'], 'storage_list_buckets')
        schema = detail['tools'][0]['inputSchema']
        self.assertNotIn('path', schema.get('properties') or {})
        self.assertNotIn('method', schema.get('properties') or {})
        self.assertNotIn('path', schema.get('required') or [])
        self.assertNotIn('method', schema.get('required') or [])

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request', return_value={'id': 'appr-1', 'status': 'pending'})
    def test_call_tool_ask_shows_real_tool_and_masks_secrets(self, _create, post, _state, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        session = self._session(token)
        arguments = {'method': 'POST', 'path': '/api/v1/buckets/', 'body': {'name': 'Ada', 'api_key': 'sekret-value'}}
        direct = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='storage_create_bucket', arguments=arguments),
            content_type='application/json',
            **self._auth(token, session_id=session),
        )
        via = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_call_tool', arguments={'name': 'storage_create_bucket', 'arguments': arguments}),
            content_type='application/json',
            **self._auth(token, session_id=session),
        )
        for response in (direct, via):
            result = response.json()['result']
            text = result['content'][0]['text']
            self.assertIn('storage_create_bucket', text)
            self.assertNotIn('ai_call_tool', text)
            self.assertNotIn('sekret-value', text)
            self.assertIn(result['structuredContent']['approval_url'], text)
            self.assertIn('human user', text)
        summary = _create.call_args.args[0]['_arguments_summary']
        self.assertIn('Ada', summary)
        self.assertNotIn('sekret-value', summary)
        self.assertIn('***', summary)
        forwarded = [
            call for call in post.call_args_list if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(forwarded, [])

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_call_tool_read_full_and_unlisted_direct_call(self, post, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        listed = set(self._names(token))
        self.assertNotIn('storage_list_buckets', listed)
        for name, arguments in (
            ('storage_list_buckets', {'method': 'GET', 'path': '/api/v1/buckets/'}),
            ('ai_call_tool', {'name': 'storage_list_buckets', 'arguments': {'method': 'GET', 'path': '/api/v1/buckets/'}}),
        ):
            response = self.client.post(
                '/c/10/mcp',
                data=_rpc('tools/call', name=name, arguments=arguments if name != 'ai_call_tool' else arguments),
                content_type='application/json',
                **self._auth(token),
            )
            self.assertEqual(response.status_code, 200, response.content)
            self.assertFalse(response.json()['result'].get('isError'))
        forwarded = [
            (call.kwargs.get('json') or {}).get('params', {}).get('name')
            for call in post.call_args_list
            if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(forwarded, ['list_buckets', 'list_buckets'])

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_cold_tools_cache_is_refilled_before_reject(self, post, _mint, _http, *_mocks):
        from apps.connector.mcp_views import _get_server, tools_list_cache_key

        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        warmed = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='storage_list_buckets', arguments={'method': 'GET', 'path': '/api/v1/buckets/'}),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertFalse(warmed.json()['result'].get('isError'), warmed.content)
        server = _get_server()
        mcp_url = server._gateway.get_service_urls()['storage']
        cache.delete(tools_list_cache_key(10, mcp_url))
        again = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='storage_list_buckets', arguments={'method': 'GET', 'path': '/api/v1/buckets/'}),
            content_type='application/json',
            **self._auth(token),
        )
        text = again.json()['result']['content'][0]['text']
        self.assertNotIn('Tool call rejected.', text)
        self.assertFalse(again.json()['result'].get('isError'), again.content)
        calls = [
            call for call in post.call_args_list if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertGreaterEqual(len(calls), 2)
        from apps.connector.mcp_views import route_cache_key

        cache.delete(tools_list_cache_key(10, mcp_url))
        cache.delete(route_cache_key(10, 'storage_list_buckets'))
        third = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='storage_list_buckets', arguments={'event_type': 'ignored-extra'}),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertFalse(third.json()['result'].get('isError'), third.content)

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request', return_value={'id': 'appr-d', 'status': 'pending'})
    def test_destructive_call_tool_has_no_session_button(self, _create, post, _state, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        session = self._session(token)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'tools/call',
                name='ai_call_tool',
                arguments={'name': 'storage_delete_bucket', 'arguments': {'method': 'DELETE'}},
            ),
            content_type='application/json',
            **self._auth(token, session_id=session),
        )
        result = response.json()['result']
        meta = result['_meta']['shellui_approval']
        self.assertEqual(meta['channel'], 'link')
        self.assertIn('storage_delete_bucket', result['content'][0]['text'])
        self.assertNotIn('inputRequests', result)
        self.assertIn(meta['approval_url'], result['content'][0]['text'])

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.approval_state', return_value='expired')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_expired_and_denied_and_consumed_match_direct_calls(self, post, _state, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        session = self._session(token)
        expired = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'tools/call',
                name='ai_call_tool',
                arguments={'name': 'storage_create_bucket', 'arguments': {'method': 'POST'}},
                _meta={'shellui_approval': {'approval_id': 'appr-old'}},
            ),
            content_type='application/json',
            **self._auth(token, session_id=session),
        )
        # A stored expired grant without a consumed row opens a fresh approval.
        self.assertIn('approval pending', expired.json()['result']['content'][0]['text'].lower())
        with patch('apps.connector.mcp_approvals.decide_approval') as decide:
            decide.return_value = Mock(ok=True, status_code=200, audit_status='client_denied', approval_status='denied')
            denied = self.client.post(
                '/c/10/mcp',
                data=_rpc(
                    'tools/call',
                    name='ai_call_tool',
                    arguments={'name': 'storage_create_bucket', 'arguments': {'method': 'POST'}},
                    _meta={'shellui_approval': {'decision': 'deny', 'approval_id': 'appr-no'}},
                ),
                content_type='application/json',
                **self._auth(token, session_id=session),
            )
        self.assertIn('denied', denied.json()['result']['content'][0]['text'].lower())
        self.assertIn('storage_create_bucket', denied.json()['result']['content'][0]['text'])
        with (
            patch('apps.connector.mcp_approvals.approval_state', return_value='approved'),
            patch(
                'apps.connector.mcp_approvals.approval_consume_detail',
                return_value=ConsumeResult(consumed=False, status_code=409, already_consumed=True),
            ),
        ):
            consumed = self.client.post(
                '/c/10/mcp',
                data=_rpc(
                    'tools/call',
                    name='storage_create_bucket',
                    arguments={'method': 'POST'},
                    _meta={'shellui_approval': {'approval_id': 'appr-used'}},
                ),
                content_type='application/json',
                **self._auth(token, session_id=session),
            )
        self.assertIn('expired', consumed.json()['result']['content'][0]['text'].lower())

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_unknown_and_unauthorized_names_suggest_next_steps(self, post, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, scope='ai')
        blocked = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_call_tool', arguments={'name': 'storage_list_buckets'}),
            content_type='application/json',
            **self._auth(token),
        )
        blocked_body = json.loads(blocked.json()['result']['content'][0]['text'])
        self.assertTrue(blocked.json()['result']['isError'])
        self.assertIn('not available', blocked_body['error'])
        scoped = _token(secret=self.secret, issuer=self.issuer, scope='ai storage')
        self._names(scoped, query='?tools=all')
        allowed = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'tools/call',
                name='ai_call_tool',
                arguments={'name': 'not_a_real_tool'},
            ),
            content_type='application/json',
            **self._auth(scoped),
        )
        hint = json.loads(allowed.json()['result']['content'][0]['text'])
        self.assertIn('ai_search_tools', hint['error'])

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_cold_cache_search_describe_and_call_load_the_catalog(self, post, _mint, _http, *_mocks):
        self._storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')

        def listed_posts() -> int:
            return sum(
                1
                for call in post.call_args_list
                if (call.kwargs.get('json') or {}).get('method') == 'tools/list'
            )

        cache.clear()
        search = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_search_tools', arguments={'query': 'list buckets', 'limit': 3}),
            content_type='application/json',
            **self._auth(token),
        )
        search_body = json.loads(search.json()['result']['content'][0]['text'])
        self.assertEqual(search_body['matches'][0]['name'], 'storage_list_buckets')
        self.assertEqual(listed_posts(), 1)

        cache.clear()
        described = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_describe_tool', arguments={'name': 'storage_list_buckets'}),
            content_type='application/json',
            **self._auth(token),
        )
        detail = json.loads(described.json()['result']['content'][0]['text'])
        self.assertEqual(detail['tools'][0]['name'], 'storage_list_buckets')
        self.assertIn('inputSchema', detail['tools'][0])
        self.assertEqual(listed_posts(), 2)

        cache.clear()
        called = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'tools/call',
                name='ai_call_tool',
                arguments={'name': 'storage_list_buckets', 'arguments': {'method': 'GET', 'path': '/api/v1/buckets/'}},
            ),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertFalse(called.json()['result'].get('isError'))
        forwarded = [
            (call.kwargs.get('json') or {}).get('params', {}).get('name')
            for call in post.call_args_list
            if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertIn('list_buckets', forwarded)

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_catalog_cache_is_isolated_by_company(self, post, _mint, _http, *_mocks):
        lists = {'n': 0}

        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') == 'tools/list':
                lists['n'] += 1
                local = 'list_alpha' if lists['n'] == 1 else 'list_beta'
                resp.json.return_value = {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'result': {
                        'tools': [
                            {
                                'name': local,
                                'description': 'List buckets',
                                'inputSchema': {
                                    'type': 'object',
                                    'properties': {
                                        'path': {'type': 'string', 'const': '/api/v1/buckets/'},
                                        'method': {'type': 'string', 'enum': ['GET']},
                                    },
                                    'required': ['path', 'method'],
                                    'additionalProperties': False,
                                },
                                '_meta': {'method': 'GET', 'path': '/api/v1/buckets/', 'read_only': True},
                            }
                        ]
                    },
                }
            else:
                resp.json.return_value = {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': False},
                }
            return resp

        post.side_effect = side_effect
        token_10 = _token(secret=self.secret, issuer=self.issuer, company_id=10)
        token_11 = _token(secret=self.secret, issuer=self.issuer, company_id=11)

        def search(company: int, token: str) -> list[str]:
            response = self.client.post(
                f'/c/{company}/mcp',
                data=_rpc('tools/call', name='ai_search_tools', arguments={'query': 'list buckets', 'limit': 5}),
                content_type='application/json',
                **self._auth(token),
            )
            body = json.loads(response.json()['result']['content'][0]['text'])
            return [match['name'] for match in body['matches']]

        first = search(10, token_10)
        second = search(10, token_10)
        other = search(11, token_11)
        again = search(10, token_10)
        self.assertEqual(first, second)
        self.assertEqual(again, first)
        self.assertIn('storage_list_alpha', first)
        self.assertIn('storage_list_beta', other)
        self.assertNotIn('storage_list_alpha', other)
        self.assertEqual(lists['n'], 2)

    def test_direct_read_names_are_stable(self, *_mocks):
        self.assertEqual(
            DIRECT_READ_TOOLS,
            ('identity_list_users', 'storage_list_bucket', 'hosting_list_apps', 'email_list_messages'),
        )
