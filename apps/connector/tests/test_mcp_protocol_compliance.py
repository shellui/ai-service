"""MCP Streamable HTTP and JSON-RPC responses validated against the 2025-06-18 schema."""

from __future__ import annotations

import json
import time
from functools import lru_cache
from pathlib import Path
from unittest.mock import patch

import jwt
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from apps.connector import mcp_protocol

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'mcp-schema-2025-06-18.json'
AI_MCP = 'https://ai.test/c/10/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'


@lru_cache
def _mcp_schema() -> dict:
    return json.loads(FIXTURES.read_text(encoding='utf-8'))


@lru_cache
def _schema_registry() -> Registry:
    return Registry().with_resources([('schema:mcp', Resource.from_contents(_mcp_schema()))])


def _validate_definition(definition: str, instance: object) -> None:
    Draft202012Validator(
        {'$ref': f'schema:mcp#/definitions/{definition}'},
        registry=_schema_registry(),
    ).validate(instance)


def _rpc(method: str, req_id=1, **params):
    body = {'jsonrpc': '2.0', 'method': method}
    if method.startswith('notifications/'):
        if params:
            body['params'] = params
    else:
        body['id'] = req_id
        body['params'] = params or {}
    return json.dumps(body)


def _agent_token(*, secret: str, issuer: str, resource: str = AI_MCP) -> str:
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': 'agent:agent-a',
        'agent_id': 'agent-a',
        'company_id': 10,
        'scope': 'ai',
        'mcp_access': 'full',
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'aud': resource,
        'iss': issuer,
        'iat': now,
        'exp': now + 3600,
    }
    return jwt.encode(claims, secret, algorithm='HS256')


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_AUDIENCE='shellui-test',
    IDENTITY_JWKS_URL='http://localhost:8000/.well-known/jwks.json',
    STORAGE_SERVICE_URL='https://storage.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    AI_PUBLIC_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-protocol-compliance',
        }
    },
)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class McpProtocolComplianceTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.secret = 'test-hs256-secret-for-mcp-gateway-tests-only'
        self.issuer = 'https://identity.test'

    def _auth(self, token: str) -> dict:
        return {'HTTP_AUTHORIZATION': f'Bearer {token}', 'HTTP_ACCEPT': MCP_ACCEPT}

    def test_initialize_result_matches_schema(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'initialize',
                protocolVersion='2025-06-18',
                capabilities={},
                clientInfo={'name': 'inspector', 'version': '1.0'},
            ),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        session_id = response.headers.get('Mcp-Session-Id')
        self.assertTrue(session_id)
        body = response.json()
        self.assertEqual(body['jsonrpc'], '2.0')
        _validate_definition('InitializeResult', body['result'])
        self.assertEqual(body['result']['protocolVersion'], '2025-06-18')
        self.assertIn('name', body['result']['serverInfo'])
        self.assertIn('version', body['result']['serverInfo'])

    def test_initialize_supported_protocol_versions_match_gateway_tuple(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        tested = set()
        for ver in mcp_protocol.SUPPORTED_PROTOCOL_VERSIONS:
            response = self.client.post(
                '/c/10/mcp',
                data=_rpc(
                    'initialize',
                    protocolVersion=ver,
                    capabilities={},
                    clientInfo={'name': 'inspector', 'version': '1.0'},
                ),
                content_type='application/json',
                **self._auth(token),
            )
            self.assertEqual(response.status_code, 200, ver)
            self.assertEqual(response.json()['result']['protocolVersion'], ver)
            tested.add(ver)
        self.assertEqual(tested, set(mcp_protocol.SUPPORTED_PROTOCOL_VERSIONS))

    def test_initialize_newer_protocol_version_answers_with_newest_supported(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'initialize',
                protocolVersion='2026-07-28',
                capabilities={},
                clientInfo={'name': 'future', 'version': '1.0'},
            ),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['result']['protocolVersion'], '2025-11-25')

    def test_initialize_negotiates_older_protocol_version(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'initialize',
                protocolVersion='2024-11-05',
                capabilities={},
                clientInfo={'name': 'legacy', 'version': '1.0'},
            ),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.json()['result']['protocolVersion'], '2024-11-05')

    def test_notifications_initialized_returns_202_without_body(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        init = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'initialize',
                protocolVersion='2025-06-18',
                capabilities={},
                clientInfo={'name': 'inspector', 'version': '1.0'},
            ),
            content_type='application/json',
            **self._auth(token),
        )
        session = init.headers['Mcp-Session-Id']
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('notifications/initialized'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_ACCEPT=MCP_ACCEPT,
            HTTP_MCP_PROTOCOL_VERSION='2025-06-18',
            HTTP_MCP_SESSION_ID=session,
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.content, b'')

    def test_tools_list_result_matches_schema(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        _validate_definition('ListToolsResult', body['result'])

    def test_unknown_method_jsonrpc_error_shape(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('resources/list'),
            content_type='application/json',
            **self._auth(token),
        )
        body = response.json()
        _validate_definition('JSONRPCError', body)
        self.assertEqual(body['error']['code'], -32601)

    def test_missing_accept_rejected(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 400)
        _validate_definition('JSONRPCError', response.json())

    def test_invalid_mcp_protocol_version_header(self, *_mocks):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_ACCEPT=MCP_ACCEPT,
            HTTP_MCP_PROTOCOL_VERSION='1999-01-01',
        )
        self.assertEqual(response.status_code, 400)
        _validate_definition('JSONRPCError', response.json())
