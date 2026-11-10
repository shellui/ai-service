"""Official MCP Python client elicitation during tools/call.

Hermes answers classic ``elicitation/create`` on the Streamable HTTP response.
This test drives that path with the SDK's ``elicitation_callback``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import Mock, patch

from django.test import LiveServerTestCase, override_settings

from apps.connector.mcp_approvals import ConsumeResult, DecideResult
from apps.connector.tests.test_mcp_discovery import STORAGE_TOOLS, _SIGNING, _token

_SETTINGS = dict(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',  # gitleaks:allow
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_AUDIENCE='shellui-test',
    IDENTITY_JWKS_URL='',
    IDENTITY_SERVICE_URL='https://identity.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    STORAGE_SERVICE_URL='https://storage.test',
    AI_PUBLIC_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    MCP_TOOLS_LIST_MODE='discovery',
    MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=5,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'hermes-elicit'}},
)


def _storage(post):
    def side_effect(url, **kwargs):
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

    post.side_effect = side_effect


async def _call_with_callback(url: str, token: str, callback):
    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.types import Implementation

    client = httpx2.AsyncClient(
        headers={'Authorization': f'Bearer {token}'},
        timeout=httpx2.Timeout(30.0, read=30.0),
    )
    try:
        async with streamable_http_client(url, http_client=client, terminate_on_close=False) as (read, write):
            async with ClientSession(
                read,
                write,
                elicitation_callback=callback,
                client_info=Implementation(name='Hermes', version='1'),
            ) as session:
                await session.initialize()
                return await session.call_tool(
                    'storage_create_bucket',
                    {'name': 'Ada'},
                    read_timeout_seconds=20,
                )
    finally:
        await client.aclose()


@override_settings(**_SETTINGS)
@patch('apps.connector.mcp_approvals.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_approval_gate.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_identity._http_post')
@patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
@patch('apps.connector.mcp_views.requests.post')
class HermesElicitationSdkTests(LiveServerTestCase):
    def setUp(self):
        from django.core.cache import cache

        cache.clear()
        self.token = _token(
            secret='test-hs256-secret-for-mcp-gateway-tests-only',  # gitleaks:allow
            issuer='https://identity.test',
            mcp_access='ask',
        )

    def _run(self, post, action: str, *, sleep_seconds: float = 0):
        from mcp.types import ElicitResult

        seen = {}

        async def callback(_context, params):
            seen['mode'] = getattr(params, 'mode', None)
            seen['message'] = str(getattr(params, 'message', '') or '')
            if sleep_seconds:
                await asyncio.sleep(sleep_seconds)
            if action == 'accept':
                return ElicitResult(action='accept', content={})
            if action == 'decline':
                return ElicitResult(action='decline')
            return ElicitResult(action='cancel')

        _storage(post)
        result = asyncio.run(_call_with_callback(f'{self.live_server_url}/c/10/mcp', self.token, callback))
        text = result.content[0].text if result.content else ''
        return seen, text, result

    def test_accept_runs_the_tool(self, post, _mint, _http, *_mocks):
        with (
            patch(
                'apps.connector.mcp_approval_gate.approvals.create_approval_request',
                return_value={
                    'id': 'appr-1',
                    'status': 'pending',
                    'approval_url': 'https://identity.test/oauth/mcp/approval/appr-1',
                },
            ),
            patch(
                'apps.connector.mcp_approval_gate.approvals.decide_approval',
                return_value=DecideResult(ok=True, status_code=200, audit_status='client_allowed', approval_status='approved'),
            ) as decide,
            patch(
                'apps.connector.mcp_approval_gate.approvals.approval_consume_detail',
                return_value=ConsumeResult(True, status_code=200),
            ),
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', return_value=None),
        ):
            seen, text, result = self._run(post, 'accept')
        self.assertEqual(seen.get('mode'), 'form')
        self.assertIn('https://identity.test/oauth/mcp/approval/appr-1', seen.get('message', ''))
        self.assertIn('human user', seen.get('message', ''))
        self.assertFalse(result.is_error)
        self.assertIn('created', text)
        self.assertEqual(decide.call_args.kwargs['decision'], 'allow')
        self.assertEqual(decide.call_args.kwargs['consent'], 'in_chat')
        self.assertEqual(decide.call_args.kwargs['client_name'], 'Hermes')

    def test_decline_does_not_run_the_tool(self, post, _mint, _http, *_mocks):
        with (
            patch(
                'apps.connector.mcp_approval_gate.approvals.create_approval_request',
                return_value={
                    'id': 'appr-1',
                    'status': 'pending',
                    'approval_url': 'https://identity.test/oauth/mcp/approval/appr-1',
                },
            ),
            patch(
                'apps.connector.mcp_approval_gate.approvals.decide_approval',
                return_value=DecideResult(ok=True, status_code=200, audit_status='client_denied', approval_status='denied'),
            ) as decide,
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', return_value=None),
        ):
            _seen, text, result = self._run(post, 'decline')
        self.assertTrue(result.is_error)
        self.assertIn('denied', text.lower())
        self.assertEqual(decide.call_args.kwargs['decision'], 'deny')
        forwarded = [
            call for call in post.call_args_list if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(forwarded, [])

    def test_cancel_returns_the_human_link(self, post, _mint, _http, *_mocks):
        with (
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
        ):
            _seen, text, result = self._run(post, 'cancel')
        self.assertFalse(result.is_error)
        self.assertIn('human user', text)
        self.assertIn('https://identity.test/oauth/mcp/approval/appr-1', text)
        decide.assert_not_called()

    @override_settings(MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=1)
    def test_timeout_falls_back_to_the_link(self, post, _mint, _http, *_mocks):
        with (
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
        ):
            _seen, text, result = self._run(post, 'accept', sleep_seconds=3)
        self.assertFalse(result.is_error)
        self.assertIn('human user', text)
        self.assertIn('https://identity.test/oauth/mcp/approval/appr-1', text)
        decide.assert_not_called()
        self.assertNotIn('created', text)
