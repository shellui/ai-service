"""Hermes-style MCP clients get an immediate pending approval URL (no tools/call hold).

LLM agents only show chat text after a tool result returns. Holding tools/call for
form elicitation left Hermes blank until timeout; the gateway now returns pending
with the raw URL immediately.
"""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from apps.connector.tests.test_mcp_discovery import STORAGE_TOOLS, _SIGNING, _token

AI_MCP = 'https://ai.test/c/10/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',  # gitleaks:allow
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    STORAGE_SERVICE_URL='https://storage.test',
    AI_PUBLIC_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_TOOLS_LIST_MODE='discovery',
    MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=90,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'hermes-immediate-pending',
        }
    },
)
@patch('apps.connector.mcp_approvals.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_approval_gate.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class HermesImmediatePendingTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.secret = 'test-hs256-secret-for-mcp-gateway-tests-only'  # gitleaks:allow
        self.issuer = 'https://identity.test'
        self.token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')

    def _auth(self, *, session_id: str | None = None) -> dict:
        headers = {'HTTP_AUTHORIZATION': f'Bearer {self.token}', 'HTTP_ACCEPT': MCP_ACCEPT}
        if session_id:
            headers['HTTP_MCP_SESSION_ID'] = session_id
        return headers

    def _session(self) -> str:
        response = self.client.post(
            '/c/10/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'initialize',
                    'params': {
                        'protocolVersion': '2025-06-18',
                        'capabilities': {'elicitation': {}},
                        'clientInfo': {'name': 'Hermes', 'version': '1'},
                    },
                }
            ),
            content_type='application/json',
            **self._auth(),
        )
        self.assertEqual(response.status_code, 200)
        return response.headers.get('Mcp-Session-Id') or response.get('Mcp-Session-Id') or ''

    def test_tools_call_returns_pending_url_without_holding_elicitation(self, *_mocks):
        session = self._session()

        def storage_post(url, **kwargs):
            resp = Mock()
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') == 'tools/call':
                resp.json.return_value = {
                    'jsonrpc': '2.0',
                    'id': payload.get('id'),
                    'result': {'content': [{'type': 'text', 'text': 'created'}], 'isError': False},
                }
            else:
                resp.json.return_value = STORAGE_TOOLS
            return resp

        with (
            patch('apps.connector.mcp_views.requests.post', side_effect=storage_post),
            patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token'),
            patch('apps.connector.mcp_identity._http_post'),
            patch(
                'apps.connector.mcp_approval_gate.approvals.create_approval_request',
                return_value={
                    'id': 'appr-1',
                    'status': 'pending',
                    'approval_url': 'https://identity.test/oauth/mcp/approval/appr-1',
                },
            ),
            patch('apps.connector.mcp_approval_gate.approvals.decide_approval') as decide,
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', return_value=None),
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
        ):
            response = self.client.post(
                '/c/10/mcp',
                data=json.dumps(
                    {
                        'jsonrpc': '2.0',
                        'id': 2,
                        'method': 'tools/call',
                        'params': {
                            'name': 'storage_create_bucket',
                            'arguments': {'name': 'Ada'},
                        },
                    }
                ),
                content_type='application/json',
                **self._auth(session_id=session),
            )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('text/event-stream', response.get('Content-Type', ''))
        result = response.json()['result']
        text = result['content'][0]['text']
        self.assertIn('https://identity.test/oauth/mcp/approval/appr-1', text)
        self.assertIn('human user', text.lower())
        self.assertIn('ai_get_approval', text)
        self.assertEqual(result['structuredContent']['status'], 'pending')
        self.assertEqual(
            result['structuredContent']['approval_url'],
            'https://identity.test/oauth/mcp/approval/appr-1',
        )
        self.assertNotIn('created', text)
        decide.assert_not_called()
