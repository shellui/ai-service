"""MCP gateway approval enforcement tests."""

from __future__ import annotations

import json
import time
from unittest.mock import Mock, patch

import jwt
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from apps.authapi.ai_service_jwks import (
    build_jwks_document,
    compute_rsa_kid,
    generate_rsa_key_pair,
    load_ai_service_signing_key,
)
from apps.connector import mcp_approval_copy as copy
from apps.connector.mcp_approval_gate import build_elicitation_meta, enforce_tool_call_approval
from apps.connector import mcp_approvals
from apps.connector.mcp_approvals import SESSION_GRANT_SECONDS
from apps.connector.mcp_protocol import MCP_SESSION_CACHE_PREFIX

AI_MCP = 'https://ai.test/c/10/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))


def _rpc(method: str, **params):
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


def _agent_token(*, secret: str, issuer: str, mcp_access: str = 'ask') -> str:
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': 'agent:agent-a',
        'agent_id': 'agent-a',
        'agent_name': 'Test Agent',
        'company_id': 10,
        'company_name': 'Acme',
        'scope': 'ai storage',
        'mcp_access': mcp_access,
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'aud': AI_MCP,
        'iss': issuer,
        'iat': now,
        'exp': now + 3600,
    }
    return jwt.encode(claims, secret, algorithm='HS256')


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    STORAGE_SERVICE_URL='https://storage.test',
    AI_PUBLIC_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-approvals-tests',
        }
    },
)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class McpApprovalGatewayTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.secret = 'test-hs256-secret-for-mcp-gateway-tests-only'
        self.issuer = 'https://identity.test'

    def _auth(self, token: str, *, session_id: str | None = None) -> dict:
        headers = {'HTTP_AUTHORIZATION': f'Bearer {token}', 'HTTP_ACCEPT': MCP_ACCEPT}
        if session_id:
            headers['HTTP_MCP_SESSION_ID'] = session_id
        return headers

    def _init_session(self, token: str, *, elicitation: bool = True) -> str:
        caps = {'elicitation': {}} if elicitation else {}
        response = self.client.post(
            '/c/10/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'initialize',
                    'params': {'protocolVersion': '2025-06-18', 'capabilities': caps},
                }
            ),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200)
        return response['Mcp-Session-Id']

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_identity.forward_call_log')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request')
    def test_write_tool_under_ask_requires_approval(self, create_approval, post, _state, _log, _mint, *_mocks):
        create_approval.return_value = {'id': 'appr-1', 'status': 'pending'}
        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {
                'tools': [
                    {
                        'name': 'create_bucket',
                        'description': 'Create bucket',
                        'annotations': {
                            'readOnlyHint': False,
                            'destructiveHint': False,
                            'idempotentHint': False,
                            'openWorldHint': True,
                        },
                        '_meta': {'method': 'post', 'path': '/api/v1/buckets/'},
                    }
                ]
            },
        }

        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') == 'tools/call':
                resp.json.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {'content': []}}
            else:
                resp.json.return_value = storage_tools
            return resp

        post.side_effect = side_effect
        token = _agent_token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        session_id = self._init_session(token)
        self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc(
                'tools/call',
                name='storage_create_bucket',
                arguments={'method': 'POST', 'path': '/api/v1/buckets/'},
            ),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['result']['isError'])
        meta = body['result']['_meta']['shellui_approval']
        self.assertEqual(meta['approval_id'], 'appr-1')
        self.assertEqual(meta['elicitation']['title'], copy.approval_title(tool_name='storage_create_bucket', destructive=False))
        self.assertIn('session_allow', meta['elicitation']['buttons'])
        create_approval.assert_called_once()
        forwarded = [
            call
            for call in post.call_args_list
            if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(forwarded, [])

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_identity.forward_call_log')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request')
    def test_destructive_hides_session_button(self, create_approval, post, _state, _log, _mint, *_mocks):
        create_approval.return_value = {'id': 'appr-2', 'status': 'pending'}
        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {
                'tools': [
                    {
                        'name': 'delete_bucket',
                        'annotations': {
                            'readOnlyHint': False,
                            'destructiveHint': True,
                            'idempotentHint': True,
                            'openWorldHint': True,
                        },
                        '_meta': {'method': 'delete', 'path': '/api/v1/buckets/{id}/'},
                    }
                ]
            },
        }

        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') != 'tools/call':
                resp.json.return_value = storage_tools
            else:
                resp.json.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {'content': []}}
            return resp

        post.side_effect = side_effect
        token = _agent_token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        session_id = self._init_session(token)
        self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='storage_delete_bucket', arguments={'method': 'DELETE'}),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        meta = response.json()['result']['_meta']['shellui_approval']
        self.assertNotIn('session_allow', meta['elicitation']['buttons'])
        self.assertIn('This can change data.', meta['elicitation']['title'])

    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_identity.forward_call_log')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_session_grant_skips_non_destructive_reprompt(self, post, _log, _mint, *_mocks):
        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {
                'tools': [
                    {
                        'name': 'create_bucket',
                        'annotations': {
                            'readOnlyHint': False,
                            'destructiveHint': False,
                            'idempotentHint': False,
                            'openWorldHint': True,
                        },
                        '_meta': {'method': 'post', 'path': '/api/v1/buckets/'},
                    }
                ]
            },
        }

        def side_effect(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') == 'tools/call':
                resp.json.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {'content': []}}
            else:
                resp.json.return_value = storage_tools
            return resp

        post.side_effect = side_effect
        token = _agent_token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        session_id = self._init_session(token)
        cache.set(
            f'{MCP_SESSION_CACHE_PREFIX}{session_id}',
            {
                'company_id': 10,
                'agent_id': 'agent-a',
                'protocol_version': '2025-06-18',
                'client_elicitation': True,
            },
            3600,
        )
        self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        with patch('apps.connector.mcp_approvals.create_approval_request') as create_approval, patch(
            'apps.connector.mcp_approvals.check_session_grant', return_value=True
        ):
            response = self.client.post(
                '/c/10/mcp',
                data=_rpc('tools/call', name='storage_create_bucket', arguments={'method': 'POST'}),
                content_type='application/json',
                **self._auth(token, session_id=session_id),
            )
            create_approval.assert_not_called()
        self.assertEqual(response.status_code, 200)
        forwarded = [
            call
            for call in post.call_args_list
            if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(len(forwarded), 1)


class McpApprovalCopyTests(TestCase):
    @override_settings(IDENTITY_ISSUER='https://identity.test')
    def test_settings_url_uses_public_approvals_path(self):
        self.assertEqual(
            mcp_approvals.approval_settings_url('abc-123'),
            'https://identity.test/api/v1/mcp/approvals/abc-123',
        )
        self.assertEqual(
            mcp_approvals.approval_settings_url(),
            'https://identity.test/api/v1/mcp/approvals',
        )

    def test_elicitation_meta_session_seconds(self):
        meta = build_elicitation_meta(
            tool_name='storage_create_bucket',
            destructive=False,
            agent_claims={'agent_name': 'Bot', 'company_name': 'Acme', 'agent_id': 'a', 'company_id': 10},
            approval_id='id-1',
        )
        self.assertEqual(meta['elicitation']['session_seconds'], SESSION_GRANT_SECONDS)
        self.assertEqual(meta['elicitation']['session_helper'], copy.session_helper_text())
