"""Aggregated ai-service /mcp gateway tests."""

from __future__ import annotations

import json
import logging
import time
from unittest.mock import Mock, patch

import jwt
import requests
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

AI_MCP = 'https://ai.test/c/10/mcp'
STORAGE_MCP = 'https://storage.test/mcp'
IDENTITY_MCP = 'https://identity.test/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'


def _rpc(method: str, **params):
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


def _agent_token(
    *,
    secret: str,
    issuer: str,
    resource: str = AI_MCP,
    agent_id: str = 'agent-a',
    company_id: int = 10,
    scope: str = 'ai storage',
) -> str:
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': f'agent:{agent_id}',
        'agent_id': agent_id,
        'company_id': company_id,
        'scope': scope,
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
            'LOCATION': 'ai-mcp-gateway-tests',
        }
    },
)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
class McpGatewayTests(TestCase):
    def setUp(self):
        cache.clear()
        # No identity in unit tests: treat agents as not revoked unless a test says otherwise.
        revoked = patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
        revoked.start()
        self.addCleanup(revoked.stop)
        self.client = Client()
        self.secret = 'test-hs256-secret-for-mcp-gateway-tests-only'
        self.issuer = 'https://identity.test'

    def _auth(self, token: str) -> dict:
        return {'HTTP_AUTHORIZATION': f'Bearer {token}', 'HTTP_ACCEPT': MCP_ACCEPT}

    def test_auth_required(self, _rev_ok):
        response = self.client.post('/c/10/mcp', data=_rpc('tools/list'), content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_wrong_audience_rejected(self, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer, resource=STORAGE_MCP)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 401)

    @patch('apps.connector.mcp_views.agent_is_revoked', return_value=True)
    def test_revoked_agent_blocked(self, _revoked, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json().get('error'), 'agent_revoked')

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_tenant_isolation_scopes_downstream_fetch(self, post, _mint, _rev_ok):
        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'tools': [{'name': 'list_buckets', 'description': 'List'}]},
        }

        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            resp.json.return_value = storage_tools
            return resp

        post.side_effect = side_effect
        token = _agent_token(secret=self.secret, issuer=self.issuer, scope='ai')
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200)
        names = {t['name'] for t in response.json()['result']['tools']}
        self.assertNotIn('storage_list_buckets', names)
        post.assert_not_called()

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_tools_list_includes_remote_when_allowed(self, post, _mint, _rev_ok):
        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'tools': [{'name': 'list_buckets', 'description': 'List'}]},
        }

        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            resp.json.return_value = storage_tools
            return resp

        post.side_effect = side_effect
        token = _agent_token(secret=self.secret, issuer=self.issuer, scope='ai storage')
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        names = {t['name'] for t in response.json()['result']['tools']}
        self.assertIn('storage_list_buckets', names)
        self.assertNotIn('list_buckets', names)
        self.assertIn('ai_list_services', names)
        self.assertNotIn('list_services', names)
        for n in names:
            self.assertNotIn('api_v1', n)
            self.assertNotIn('__', n)

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post', side_effect=requests.Timeout('slow'))
    def test_downstream_timeout_omits_remote_tools(self, _post, _mint, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer, scope='ai storage')
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200)
        names = {t['name'] for t in response.json()['result']['tools']}
        self.assertNotIn('storage_list_buckets', names)

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='mcp-test-token-leak-check')
    @patch('shellui_django.mcp.gateway.requests.post', side_effect=ConnectionError('down'))
    def test_gateway_logs_never_include_bearer_token(self, _post, _mint, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer, scope='ai storage')
        with self.assertLogs('shellui_django.mcp.gateway', level='WARNING') as logs:
            self.client.post(
                '/c/10/mcp',
                data=_rpc('tools/call', name='storage_list_buckets'),
                content_type='application/json',
                **self._auth(token),
            )
        joined = '\n'.join(logs.output)
        self.assertNotIn('mcp-test-token-leak-check', joined)
        self.assertNotIn('Bearer', joined)

    def test_legacy_downstream_name_is_canonicalized_on_export(self, _rev_ok):
        from apps.connector.mcp_views import prefixed_tool_catalog

        routes: dict[str, tuple[str, str]] = {}

        def remember(export_name: str, sid: str, downstream: str) -> None:
            routes[export_name] = (sid, downstream)

        remote = {
            'identity': [{'name': 'api_v1_users_list', 'description': 'List users'}],
        }
        names = [t['name'] for t in prefixed_tool_catalog([], remote, remember_route=remember)]
        self.assertEqual(names, ['identity_list_users'])
        self.assertEqual(routes['identity_list_users'], ('identity', 'api_v1_users_list'))

    def test_every_downstream_tool_gets_service_prefix(self, _rev_ok):
        from apps.connector.mcp_views import prefixed_tool_catalog

        local = [{'name': 'dup_tool', 'description': 'local'}]
        remote = {
            'storage': [{'name': 'dup_tool'}, {'name': 'unique_tool'}],
            'identity': [{'name': 'unique_tool'}],
        }
        names = [t['name'] for t in prefixed_tool_catalog(local, remote)]
        self.assertEqual(
            names,
            ['ai_dup_tool', 'storage_dup_tool', 'storage_unique_tool', 'identity_unique_tool'],
        )

    def test_list_services_tools_call(self, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_list_services', arguments={}),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertNotIn('error', body.get('result') or body)

    def test_route_comes_from_prefix_only(self, _rev_ok):
        from apps.connector.mcp_views import _get_server

        server = _get_server()
        self.assertEqual(
            server._lookup_route('storage_list_buckets'),
            {'service_id': 'storage', 'downstream_name': 'list_buckets'},
        )
        self.assertIsNone(server._lookup_route('list_buckets'))
        self.assertIsNone(server._lookup_route('unknown_tool'))
        self.assertIsNone(server._lookup_route('ai_list_services'))
        self.assertIsNone(server._lookup_route('list_services'))

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_unprefixed_downstream_call_is_unknown(self, post, _mint, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer, scope='ai storage')
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='list_buckets'),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.json())
        post.assert_not_called()

    def test_token_for_other_company_is_refused(self, _rev_ok):
        # aud names company 11 and matches the URL, but company_id is 10: refuse.
        token = _agent_token(secret=self.secret, issuer=self.issuer, resource='https://ai.test/c/11/mcp')
        response = self.client.post(
            '/c/11/mcp', data=_rpc('tools/list'), content_type='application/json', **self._auth(token)
        )
        self.assertEqual(response.status_code, 401)
        # A valid company 10 token on company 11's URL: refuse.
        token = _agent_token(secret=self.secret, issuer=self.issuer)
        response = self.client.post(
            '/c/11/mcp', data=_rpc('tools/list'), content_type='application/json', **self._auth(token)
        )
        self.assertEqual(response.status_code, 401)

    def test_audience_ignores_request_host(self, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer, resource='http://evil.test/c/10/mcp')
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_HOST='evil.test',
            **self._auth(token),
        )
        # Django refuses the unknown host (400); either way the token is never accepted.
        self.assertIn(response.status_code, (400, 401))

    def test_unauthenticated_points_to_company_metadata(self, _rev_ok):
        response = self.client.post('/c/10/mcp', data=_rpc('tools/list'), content_type='application/json')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response['WWW-Authenticate'],
            'Bearer resource_metadata="https://ai.test/.well-known/oauth-protected-resource/c/10/mcp"',
        )

    def test_company_metadata_uses_exact_resource(self, _rev_ok):
        response = self.client.get('/.well-known/oauth-protected-resource/c/10/mcp')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['resource'], 'https://ai.test/c/10/mcp')
        self.assertEqual(body['authorization_servers'], ['https://identity.test'])

    def test_plain_mcp_has_no_default_company(self, _rev_ok):
        token = _agent_token(secret=self.secret, issuer=self.issuer, resource='https://ai.test/mcp')
        response = self.client.post('/mcp', data=_rpc('tools/list'), content_type='application/json', **self._auth(token))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()['error'], 'company_required')
        response = self.client.get('/.well-known/oauth-protected-resource')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()['error'], 'company_required')

    def test_invalid_company_ids_are_404(self, _rev_ok):
        for path in ('/c/0/mcp', '/c/abc/mcp', '/c/-1/mcp', '/.well-known/oauth-protected-resource/c/0/mcp'):
            if 'well-known' in path:
                response = self.client.get(path)
            else:
                response = self.client.post(path, data=_rpc('tools/list'), content_type='application/json')
            self.assertEqual(response.status_code, 404, path)
