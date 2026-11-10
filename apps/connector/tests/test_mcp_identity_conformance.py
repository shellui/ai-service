"""Mocked Identity conformance: approval create → state → human decide → consume.

Uses ``requests.post`` side effects only (no real Identity). Asserts JSON bodies never include
``arguments`` or ``arguments_redacted``.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import jwt
from django.test import Client, TestCase, override_settings


def _ok_json(data: dict) -> MagicMock:
    m = MagicMock(status_code=200)
    m.json.return_value = data
    return m

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))

AI_MCP = 'https://ai.test/c/10/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'


def _rpc(method: str, **params):
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


def _token(*, mcp_access: str = 'ask') -> str:
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': 'agent:conf-a',
        'agent_id': 'conf-agent',
        'agent_name': 'Conf',
        'company_id': 10,
        'company_name': 'Acme',
        'scope': 'ai storage',
        'mcp_access': mcp_access,
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'aud': AI_MCP,
        'iss': 'https://identity.test',
        'iat': now,
        'exp': now + 3600,
    }
    return jwt.encode(claims, 'test-hs256-secret-for-mcp-gateway-tests-only', algorithm='HS256')


@override_settings(
    DEBUG=True,
    ALLOWED_HOSTS=('testserver', 'localhost', '127.0.0.1', 'ai.test'),
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',  # gitleaks:allow
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    STORAGE_SERVICE_URL='https://storage.test',
    AI_PUBLIC_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=0,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-identity-conformance',
        }
    },
)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_approval_gate.agent_is_revoked', return_value=False)
class McpIdentityConformanceTests(TestCase):
    def test_approval_flow_http_bodies_no_arguments(self, *_mocks):
        """State before create finds pending id; client allow → consume; POST JSON is minimal."""
        client = Client()
        token = _token()
        headers = {'HTTP_AUTHORIZATION': f'Bearer {token}', 'HTTP_ACCEPT': MCP_ACCEPT}

        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {
                'tools': [
                    {
                        'name': 'delete_bucket',
                        'description': 'Del',
                        'inputSchema': {'type': 'object'},
                        'annotations': {'destructiveHint': True},
                        '_meta': {
                            'path': '/api/v1/buckets/{id}/',
                            'method': 'DELETE',
                            'operation_summary': 'Delete bucket',
                        },
                    },
                ]
            },
        }

        approvals: list[dict] = []
        state_calls = {'n': 0}

        def http_post(url, **kwargs):
            """Single handler: inner ``patch(..., gateway.requests.post)`` shadows ``requests.post`` globally."""
            u = str(url).split('?', 1)[0]
            jb = kwargs.get('json') if isinstance(kwargs.get('json'), dict) else {}
            if 'storage.test' in u and 'tools/list' in str(jb):
                return _ok_json(storage_tools)
            if 'storage.test' in u and jb and jb.get('method') == 'tools/call':
                body = {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'result': {'content': [], 'isError': False},
                }
                m = MagicMock(status_code=200, content=json.dumps(body).encode())
                m.json.return_value = body
                return m
            if 'identity.test' not in u:
                return MagicMock(status_code=404)
            if 'mcp-call-logs' in u:
                approvals.append({'_call_log': True, **jb})
                return _ok_json({})
            if jb.keys() == {'is_destructive'}:
                approvals.append(dict(jb))
                return _ok_json({'id': 'appr-e2e', 'status': 'pending'})
            if jb == {}:
                state_calls['n'] += 1
                status = 'pending' if state_calls['n'] == 1 else 'approved'
                return _ok_json(
                    {
                        'id': 'appr-e2e',
                        'status': status,
                        'expires_at': '2026-11-10T22:00:00+00:00',
                        'is_destructive': True,
                        'approval_url': 'https://identity.test/oauth/mcp/approval/appr-e2e?token=signed',
                    }
                )
            if 'decision' in jb and 'approval_id' in jb:
                return _ok_json({'status': 'approved', 'audit_status': 'ok'})
            if jb.keys() == {'approval_id'}:
                return _ok_json({'consumed': True})
            return MagicMock(status_code=404)

        with patch('apps.connector.mcp_identity.forward_call_log'):
            with patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='ds'):
                with patch('shellui_django.mcp.gateway.requests.post', side_effect=http_post):
                        r1 = client.post(
                            '/c/10/mcp',
                            data=_rpc('tools/call', name='storage_delete_bucket', arguments={}),
                            content_type='application/json',
                            HTTP_HOST='ai.test',
                            **headers,
                        )
                        self.assertEqual(r1.status_code, 200)
                        body1 = json.loads(r1.content)
                        self.assertFalse(body1.get('result', {}).get('isError'))
                        appr = (body1.get('result') or {}).get('_meta', {}).get('shellui_approval', {})
                        self.assertEqual(appr.get('approval_id'), 'appr-e2e')
                        self.assertEqual(appr.get('status'), 'pending')
                        self.assertTrue(str(appr.get('approval_url') or '').startswith('https://identity.test/'))

                        r2 = client.post(
                            '/c/10/mcp',
                            data=_rpc('tools/call', name='storage_delete_bucket', arguments={}),
                            content_type='application/json',
                            HTTP_HOST='ai.test',
                            **headers,
                        )
                        self.assertEqual(r2.status_code, 200)
                        body2 = json.loads(r2.content)
                        self.assertFalse(body2.get('result', {}).get('isError'))

        for row in approvals:
            if row.get('_call_log'):
                continue
            self.assertNotIn('arguments', row)
            self.assertNotIn('arguments_redacted', row)
            if 'approval_id' in row:
                self.assertEqual(set(row.keys()), {'approval_id'})
            else:
                self.assertEqual(row, {'is_destructive': True})
