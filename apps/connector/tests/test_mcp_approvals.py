"""MCP gateway approval enforcement tests."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from unittest.mock import Mock, patch

import jwt
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.connector.models import McpCallLog
from apps.authapi.ai_service_jwks import (
    build_jwks_document,
    compute_rsa_kid,
    generate_rsa_key_pair,
    load_ai_service_signing_key,
)
from apps.connector import mcp_approval_copy as copy
from apps.connector.mcp_approval_gate import (
    _log_result_from_decide,
    build_elicitation_meta,
    enforce_tool_call_approval,
)
from shellui_django.mcp.write_gate import WriteGateDecision
from apps.connector import mcp_approvals
from apps.connector.mcp_approvals import SESSION_GRANT_SECONDS, ConsumeResult, DecideResult
from apps.connector.mcp_protocol import MCP_SESSION_CACHE_PREFIX

AI_MCP = 'https://ai.test/c/10/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'

_DEFAULT_TEST_AGENT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))


def _delegated_authority_transport_mock(url, **kwargs):
    """Stub Identity internal HTTP used by gateway precheck and call-log forward."""
    u = str(url).rstrip('/')
    resp = Mock()
    if u.endswith('/mcp-agent-delegated-authority'):
        resp.status_code = 404
        return resp
    if u.endswith('/mcp-call-logs'):
        resp.status_code = 204
        return resp
    raise AssertionError(f'Unexpected identity _http_post URL: {url!r}')


def _rpc(method: str, **params):
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


def _agent_token(*, secret: str, issuer: str, mcp_access: str = 'ask', agent_id: str = _DEFAULT_TEST_AGENT_ID) -> str:
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': f'agent:{agent_id}',
        'agent_id': agent_id,
        'agent_name': 'Test Agent',
        'company_id': 10,
        'company_name': 'Acme',
        'scope': 'ai storage',
        'mcp_access': mcp_access,
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'grant_version': 1,
        'aud': AI_MCP,
        'iss': issuer,
        'iat': now,
        'exp': now + 3600,
    }
    return jwt.encode(claims, secret, algorithm='HS256')


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
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-approvals-tests',
        }
    },
    MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=0,
)
@patch('apps.connector.mcp_approval_gate.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class McpApprovalGatewayTests(TestCase):
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

    @patch('apps.connector.mcp_identity._http_post', side_effect=_delegated_authority_transport_mock)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request')
    def test_write_tool_under_ask_requires_approval(
        self, create_approval, post, _state, _mint, *_mocks
    ):
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
        self.assertFalse(body['result']['isError'])
        meta = body['result']['_meta']['shellui_approval']
        self.assertEqual(meta['approval_id'], 'appr-1')
        self.assertEqual(meta['status'], 'pending')
        self.assertEqual(meta['channel'], 'link')
        structured = body['result']['structuredContent']
        self.assertEqual(structured['status'], 'pending')
        self.assertEqual(structured['approval_url'], meta['approval_url'])
        text = body['result']['content'][0]['text']
        self.assertIn(meta['approval_url'], text)
        self.assertIn('human user', text)
        self.assertIn('Do not open, fetch, or sign in', text)
        self.assertIn('clickable link', text)
        self.assertNotIn('\u2014', text)
        self.assertNotIn('\u2013', text)
        self.assertNotIn('inputRequests', body['result'])
        create_approval.assert_called_once()
        forwarded = [
            call
            for call in post.call_args_list
            if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(forwarded, [])

    @override_settings(
        EMAIL_SERVICE_URL='https://email.test',
        EMAIL_SERVICE_API_KEY='esk_test_personal_approval',  # gitleaks:allow
    )
    @patch('apps.connector.mcp_identity._http_post', side_effect=_delegated_authority_transport_mock)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_views.requests.post')
    @patch('apps.connector.mcp_approvals.requests.post')
    def test_personal_grant_version_ai_call_tool_returns_pending_approval(
        self, identity_post, views_post, gateway_post, _mint, *_mocks
    ):
        """Device-login personal token (grant_version, no global fields) can ask for a write."""

        email_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {
                'tools': [
                    {
                        'name': 'create_template_versions',
                        'description': 'Save a new version of an email template',
                        'annotations': {
                            'readOnlyHint': False,
                            'destructiveHint': False,
                            'idempotentHint': False,
                            'openWorldHint': True,
                        },
                        '_meta': {
                            'method': 'post',
                            'path': '/api/v1/templates/{template_id}/versions',
                            'read_only': False,
                            'destructive': False,
                        },
                    }
                ]
            },
        }

        def post_side_effect(url, **kwargs):
            # mcp_views and mcp_approvals both bind the requests module, so one
            # dispatcher covers catalog fetch and identity approval calls.
            path = str(url).rstrip('/')
            resp = Mock()
            if path.endswith('/mcp-approval-state') or path.endswith('/mcp-approval-session-check'):
                resp.status_code = 404
                resp.json.return_value = {}
                return resp
            if path.endswith('/mcp-approval-requests'):
                resp.status_code = 201
                resp.json.return_value = {'id': 'appr-email-template', 'status': 'pending'}
                return resp
            resp.status_code = 200
            payload = kwargs.get('json') or {}
            if payload.get('method') == 'tools/call':
                resp.json.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {'content': []}}
            else:
                resp.json.return_value = email_tools
            return resp

        identity_post.side_effect = post_side_effect
        views_post.side_effect = post_side_effect
        gateway_post.side_effect = post_side_effect
        now = int(time.time())
        agent_id = _DEFAULT_TEST_AGENT_ID
        claims = {
            'token_type': 'access',
            'agent_id': agent_id,
            'sub': f'agent:{agent_id}',
            'company_id': 1,
            'company_name': 'Acme',
            'mcp_access': 'ask',
            'mcp_read': 'safe',
            'mcp_destructive': False,
            'scope': 'ai email',
            'jti': 'device-jti-personal',
            'iat': now,
            'exp': now + 900,
            'aud': 'https://ai.test/c/1/mcp',
            'iss': self.issuer,
            'grant_version': 1,
        }
        token = jwt.encode(claims, self.secret, algorithm='HS256')
        session_id = self.client.post(
            '/c/1/mcp',
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
        self.assertEqual(session_id.status_code, 200, session_id.content)
        mcp_session = session_id['Mcp-Session-Id']
        listed = self.client.post(
            '/c/1/mcp',
            data=_rpc('tools/list', tools='all'),
            content_type='application/json',
            **self._auth(token, session_id=mcp_session),
        )
        self.assertEqual(listed.status_code, 200, listed.content)
        names = {tool['name'] for tool in listed.json()['result']['tools']}
        self.assertIn('email_create_template_versions', names)
        response = self.client.post(
            '/c/1/mcp',
            data=_rpc(
                'tools/call',
                name='ai_call_tool',
                arguments={
                    'name': 'email_create_template_versions',
                    'arguments': {'method': 'POST', 'path': '/api/v1/templates/tpl/versions'},
                },
            ),
            content_type='application/json',
            **self._auth(token, session_id=mcp_session),
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        text = body['result']['content'][0]['text']
        self.assertNotIn('Approval unavailable.', text)
        meta = body['result']['_meta']['shellui_approval']
        self.assertEqual(meta['approval_id'], 'appr-email-template')
        self.assertEqual(meta['status'], 'pending')
        self.assertEqual(meta['channel'], 'link')
        text = body['result']['content'][0]['text']
        self.assertIn(meta['approval_url'], text)
        self.assertIn('human user', text)
        self.assertIn('email_create_template_versions', text)
        create_calls = [
            call
            for post in (identity_post, views_post, gateway_post)
            for call in post.call_args_list
            if call.args and str(call.args[0]).rstrip('/').endswith('/mcp-approval-requests')
        ]
        self.assertEqual(len(create_calls), 1)
        assertion = create_calls[0].kwargs['headers']['Authorization'].split(' ', 1)[1]
        signed = jwt.decode(assertion, options={'verify_signature': False})
        self.assertEqual(signed.get('grant_version'), 1)
        self.assertNotIn('global_company_id', signed)
        self.assertNotIn('company_binding_version', signed)
        forwarded = [
            call
            for call in list(views_post.call_args_list) + list(gateway_post.call_args_list)
            if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(forwarded, [])

    @patch('apps.connector.mcp_identity._http_post', side_effect=_delegated_authority_transport_mock)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request')
    def test_destructive_hides_session_button(self, create_approval, post, _state, _mint, *_mocks):
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
        result = response.json()['result']
        meta = result['_meta']['shellui_approval']
        self.assertEqual(meta['channel'], 'link')
        self.assertIn('approval_url', meta)
        self.assertNotIn('inputRequests', result)
        self.assertNotIn('elicitation', meta)

    @patch('apps.connector.mcp_identity._http_post', side_effect=_delegated_authority_transport_mock)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_session_grant_skips_non_destructive_reprompt(self, post, _mint, *_mocks):
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
                'agent_id': _DEFAULT_TEST_AGENT_ID,
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

    @patch('apps.connector.mcp_identity._http_post', side_effect=_delegated_authority_transport_mock)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_call_log_http200_success_not_pending(
        self,
        post,
        _mint,
        _proto_post,
        _mcp_views_agent_revoked,
        _identity_revocation_ok,
        _gate_agent_revoked,
    ):
        post.side_effect = AssertionError('downstream MCP POST should not run for local ai_list_services')
        token = _agent_token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        session_id = self._init_session(token)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_list_services', arguments={}),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(response.json()['result'].get('isError', True))
        rows = list(McpCallLog.objects.filter(company_id=10, tool_name='ai_list_services'))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'allowed')
        self.assertEqual(rows[0].status_code, 200)
        self.assertEqual(rows[0].service, 'ai')

    @patch('apps.connector.mcp_identity._http_post', side_effect=_delegated_authority_transport_mock)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_call_log_unknown_tool_is_error_not_pending(
        self,
        post,
        _mint,
        _proto_post,
        _mcp_views_agent_revoked,
        _identity_revocation_ok,
        _gate_agent_revoked,
    ):
        post.side_effect = AssertionError('downstream MCP POST should not run for unknown tool')
        token = _agent_token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        session_id = self._init_session(token)
        response = self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='ai_definitely_missing_tool', arguments={}),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()['result'].get('isError'))
        rows = list(McpCallLog.objects.filter(company_id=10, tool_name='ai_definitely_missing_tool'))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'failed')
        self.assertEqual(rows[0].status_code, 200)


class LogResultFromDecideTests(TestCase):
    """``_log_result_from_decide`` must not map ``approval_status=approved`` alone to authority success."""

    def test_http200_with_pending_audit_is_pending_not_identity_approved(self):
        decided = DecideResult(
            ok=True,
            status_code=200,
            approval_status='approved',
            audit_status='pending',
        )
        self.assertEqual(_log_result_from_decide(decided, fallback='client_allowed'), 'pending')

    def test_http200_ok_audit_with_approved_is_identity_approved(self):
        decided = DecideResult(ok=True, status_code=200, approval_status='approved', audit_status='ok')
        self.assertEqual(_log_result_from_decide(decided, fallback='client_allowed'), 'identity_approved')

    def test_not_ok_returns_error(self):
        decided = DecideResult(
            ok=False,
            status_code=409,
            approval_status='approved',
            audit_status='pending',
        )
        self.assertEqual(_log_result_from_decide(decided, fallback='client_allowed'), 'error')


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
        self.assertEqual(
            meta['elicitation']['session_helper'], copy.session_helper_text(seconds=SESSION_GRANT_SECONDS)
        )

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_elicitation_meta_setup_session_seconds(self):
        now = int(time.time())
        setup_exp = timezone.now() + timedelta(seconds=650)
        meta = build_elicitation_meta(
            tool_name='storage_create_bucket',
            destructive=False,
            agent_claims={
                'agent_name': 'Bot',
                'company_name': 'Acme',
                'agent_id': 'a',
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': 42,
                'company_binding_version': 7,
                'global_company_id': '11111111-1111-4111-8111-111111111111',
                'setup_expires_at': setup_exp.isoformat(),
                'iat': now,
                'exp': now + 900,
            },
            approval_id='id-2',
        )
        self.assertEqual(meta['elicitation']['session_seconds'], 600)
        self.assertIn('600', meta['elicitation']['session_helper'])


class McpApprovalGateDenyPrecedenceTests(TestCase):
    def test_client_deny_processed_before_session_grant(self):
        request = Mock()
        request.headers = {'Mcp-Session-Id': 'sess-1'}
        tool = {'annotations': {'readOnlyHint': False}, '_meta': {'method': 'POST', 'path': '/api/v1/x'}}
        with (
            patch('apps.connector.mcp_approval_gate.decide_write') as decide,
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write') as sess,
            patch('apps.connector.mcp_approval_gate.approvals.decide_approval') as decide_remote,
        ):
            decide.return_value = WriteGateDecision(
                allowed=False,
                needs_approval=True,
                reason='Write requires approval.',
            )
            sess.return_value = True
            decide_remote.return_value = Mock(
                ok=True,
                status_code=200,
                audit_status='client_denied',
                approval_status='denied',
            )
            out = enforce_tool_call_approval(
                request,
                1,
                params={
                    '_meta': {
                        'shellui_approval': {
                            'decision': 'deny',
                            'approval_id': 'ap-deny',
                        },
                    },
                },
                agent_claims={
                    'agent_id': 'a1',
                    'company_id': 10,
                    'mcp_access': 'ask',
                },
                export_name='storage_create_bucket',
                service_id='storage',
                tool=tool,
                method='POST',
                path='/api/v1/buckets/',
                arguments={},
            )
        sess.assert_not_called()
        self.assertFalse(out.proceed)
        self.assertIsNotNone(out.log)
        assert out.log is not None
        self.assertEqual(out.log.get('approval_id'), 'ap-deny')
        self.assertEqual(out.log.get('outcome'), 'denied')

    def test_destructive_session_allow_does_not_execute(self):
        request = Mock()
        request.headers = {'Mcp-Session-Id': 'sess-1'}
        tool = {
            'annotations': {'readOnlyHint': False, 'destructiveHint': True},
            '_meta': {'method': 'DELETE', 'path': '/api/v1/buckets/{id}/', 'destructive': True},
        }
        approval_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        with (
            patch('apps.connector.mcp_approval_gate.decide_write') as decide,
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
            patch('apps.connector.mcp_approval_gate.approvals.decide_approval') as decide_remote,
            patch('apps.connector.mcp_approval_gate.approvals.approval_consume_detail') as consume,
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', return_value='pending'),
        ):
            decide.return_value = WriteGateDecision(
                allowed=False,
                needs_approval=True,
                reason='Write requires approval.',
            )
            out = enforce_tool_call_approval(
                request,
                1,
                params={'_meta': {'shellui_approval': {'decision': 'session_allow', 'approval_id': approval_id}}},
                agent_claims={'agent_id': 'a1', 'company_id': 10, 'mcp_access': 'ask'},
                export_name='storage_delete_bucket',
                service_id='storage',
                tool=tool,
                method='DELETE',
                path='/api/v1/buckets/{id}/',
                arguments={},
            )
        decide_remote.assert_not_called()
        consume.assert_not_called()
        self.assertFalse(out.proceed)
        self.assertIsNotNone(out.log)
        assert out.log is not None
        self.assertEqual(out.log.get('access_kind'), 'destructive')
        self.assertNotEqual(out.log.get('outcome'), 'session_used')
        self.assertEqual(out.log.get('outcome'), 'pending_approval')
        self.assertEqual(out.log.get('approval_id'), approval_id)

    def test_meta_allow_cannot_self_approve(self):
        def _pending_state(payload):
            payload['approval_id'] = 'appr-self'
            payload['approval_url_field'] = 'https://identity.test/oauth/mcp/approval/appr-self'
            return 'pending'

        for destructive, export_name, method in (
            (False, 'storage_create_bucket', 'POST'),
            (True, 'storage_delete_bucket', 'DELETE'),
        ):
            request = Mock()
            request.headers = {'Mcp-Session-Id': 'sess-1'}
            tool = {
                'annotations': {'readOnlyHint': False, 'destructiveHint': destructive},
                '_meta': {
                    'method': method,
                    'path': '/api/v1/buckets/',
                    'read_only': False,
                    'destructive': destructive,
                },
            }
            for decision_name in ('allow', 'session_allow'):
                with (
                    patch('apps.connector.mcp_approval_gate.decide_write') as decide_gate,
                    patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
                    patch('apps.connector.mcp_approval_gate.approvals.approval_state', side_effect=_pending_state),
                    patch('apps.connector.mcp_approval_gate.approvals.decide_approval') as decide_remote,
                    patch('apps.connector.mcp_approval_gate.approvals.approval_consume_detail') as consume,
                    patch('apps.connector.mcp_approval_gate.approvals.create_approval_request') as create,
                ):
                    decide_gate.return_value = WriteGateDecision(
                        allowed=False, needs_approval=True, reason='Write requires approval.'
                    )
                    create.return_value = {
                        'id': 'appr-self',
                        'status': 'pending',
                        'approval_url': 'https://identity.test/oauth/mcp/approval/appr-self',
                    }
                    out = enforce_tool_call_approval(
                        request,
                        3,
                        params={
                            '_meta': {
                                'shellui_approval': {
                                    'decision': decision_name,
                                    'approval_id': 'appr-self',
                                }
                            }
                        },
                        agent_claims=_gate_claims(),
                        export_name=export_name,
                        service_id='storage',
                        tool=tool,
                        method=method,
                        path='/api/v1/buckets/',
                        arguments={'method': method},
                    )
                decide_remote.assert_not_called()
                consume.assert_not_called()
                self.assertFalse(out.proceed)
                text = json.loads(out.response.content)['result']['content'][0]['text']
                self.assertIn('https://identity.test/oauth/mcp/approval/appr-self', text)
                self.assertIn('human user', text)

    def test_retry_reuses_pending_approval(self):
        creates = {'n': 0}

        def state(payload):
            if creates['n']:
                payload['approval_id'] = 'appr-1'
                payload['approval_url_field'] = 'https://identity.test/oauth/mcp/approval/appr-1'
                return 'pending'
            return None

        def create(payload, is_destructive=False):
            creates['n'] += 1
            return {
                'id': 'appr-1',
                'status': 'pending',
                'approval_url': 'https://identity.test/oauth/mcp/approval/appr-1',
            }

        request = Mock()
        request.headers = {'Mcp-Session-Id': 'sess-1'}
        with (
            patch('apps.connector.mcp_approval_gate.decide_write') as decide,
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', side_effect=state),
            patch('apps.connector.mcp_approval_gate.approvals.create_approval_request', side_effect=create),
        ):
            decide.return_value = WriteGateDecision(
                allowed=False, needs_approval=True, reason='Write requires approval.'
            )
            first = enforce_tool_call_approval(
                request, 1, params={}, agent_claims=_gate_claims(),
                export_name='storage_create_bucket', service_id='storage', tool=_gate_tool(),
                method='POST', path='/api/v1/buckets/', arguments={'name': 'Ada'},
            )
            second = enforce_tool_call_approval(
                request, 2, params={}, agent_claims=_gate_claims(),
                export_name='storage_create_bucket', service_id='storage', tool=_gate_tool(),
                method='POST', path='/api/v1/buckets/', arguments={'name': 'Ada'},
            )
        self.assertEqual(creates['n'], 1)
        self.assertFalse(first.proceed)
        self.assertFalse(second.proceed)
        second_body = json.loads(second.response.content)
        self.assertEqual(second_body['result']['structuredContent']['approval_id'], 'appr-1')

    def test_duplicate_consumed_destructive_is_failed_with_approval(self):
        request = Mock()
        request.headers = {'Mcp-Session-Id': 'sess-1'}
        tool = {
            'annotations': {'readOnlyHint': False, 'destructiveHint': True},
            '_meta': {'method': 'DELETE', 'path': '/api/v1/buckets/{id}/', 'destructive': True},
        }
        approval_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        with (
            patch('apps.connector.mcp_approval_gate.decide_write') as decide,
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', return_value='expired'),
            patch('apps.connector.mcp_approval_gate.approvals.approval_consume_detail') as consume,
        ):
            decide.return_value = WriteGateDecision(
                allowed=False,
                needs_approval=True,
                reason='Write requires approval.',
            )
            consume.return_value = ConsumeResult(False, status_code=409, already_consumed=True)
            out = enforce_tool_call_approval(
                request,
                1,
                params={'_meta': {'shellui_approval': {'approval_id': approval_id}}},
                agent_claims={'agent_id': 'a1', 'company_id': 10, 'mcp_access': 'ask'},
                export_name='storage_delete_bucket',
                service_id='storage',
                tool=tool,
                method='DELETE',
                path='/api/v1/buckets/{id}/',
                arguments={},
            )
        self.assertFalse(out.proceed)
        self.assertIsNotNone(out.log)
        assert out.log is not None
        self.assertEqual(out.log.get('outcome'), 'failed')
        self.assertEqual(out.log.get('access_kind'), 'destructive')
        self.assertEqual(out.log.get('approval_id'), approval_id)
        self.assertNotEqual(out.log.get('outcome'), 'session_used')
        self.assertNotEqual(out.log.get('outcome'), 'allowed')


@override_settings(
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
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-destructive-tests',
        }
    },
)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class McpDestructiveOverrideTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.secret = 'test-hs256-secret-for-mcp-gateway-tests-only'  # gitleaks:allow
        self.issuer = 'https://identity.test'
        jwks_patcher = patch('apps.authapi.agent_tokens.get_jwks_client')
        self.jwks_mock = jwks_patcher.start()
        self.addCleanup(jwks_patcher.stop)
        self.jwks_mock.return_value.get_signing_key.return_value = None

    def _auth(self, token: str, *, session_id: str | None = None) -> dict:
        headers = {'HTTP_AUTHORIZATION': f'Bearer {token}', 'HTTP_ACCEPT': MCP_ACCEPT}
        if session_id:
            headers['HTTP_MCP_SESSION_ID'] = session_id
        return headers

    def _init_session(self, token: str) -> str:
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
        self.assertEqual(response.status_code, 200)
        return response['Mcp-Session-Id']

    @patch('apps.connector.mcp_identity._http_post', side_effect=_delegated_authority_transport_mock)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request')
    def test_mcp_destructive_does_not_bypass_destructive_approval(self, create_approval, post, _mint, *_mocks):
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
        now = int(time.time())
        claims = {
            'token_type': 'access',
            'sub': f'agent:{_DEFAULT_TEST_AGENT_ID}',
            'agent_id': _DEFAULT_TEST_AGENT_ID,
            'agent_name': 'Test Agent',
            'company_id': 10,
            'company_name': 'Acme',
            'scope': 'ai storage',
            'mcp_access': 'full',
            'mcp_read': 'safe',
            'mcp_destructive': True,
            'grant_version': 1,
            'aud': AI_MCP,
            'iss': self.issuer,
            'iat': now,
            'exp': now + 3600,
        }
        token = jwt.encode(claims, self.secret, algorithm='HS256')
        session_id = self._init_session(token)
        self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', name='storage_delete_bucket', arguments={'method': 'DELETE'}),
            content_type='application/json',
            **self._auth(token, session_id=session_id),
        )
        create_approval.assert_called_once()


def _gate_tool() -> dict:
    return {
        'annotations': {'readOnlyHint': False, 'destructiveHint': False},
        '_meta': {'method': 'POST', 'path': '/api/v1/buckets/', 'read_only': False, 'destructive': False},
    }


def _gate_claims() -> dict:
    return {
        'agent_id': 'a1',
        'company_id': 10,
        'mcp_access': 'ask',
        'agent_name': 'Ada',
        'company_name': 'Acme',
    }


@override_settings(
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    MCP_APPROVAL_URL_ELICITATION_WAIT_SECONDS=0,
    MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=0,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-approval-link-tests',
        }
    },
)
class ApprovalLinkGateTests(TestCase):
    def setUp(self):
        cache.clear()

    def _request(self) -> Mock:
        request = Mock()
        request.headers = {'Mcp-Session-Id': 'sess-link'}
        return request

    def _run(self, *, params: dict | None = None, state, consume=None, created=None):
        request = self._request()
        with (
            patch('apps.connector.mcp_approval_gate.decide_write') as decide,
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', side_effect=state),
            patch('apps.connector.mcp_approval_gate.approvals.approval_consume_detail', side_effect=consume),
            patch(
                'apps.connector.mcp_approval_gate.approvals.create_approval_request',
                return_value=created if created is not None else {'id': 'appr-1', 'status': 'pending'},
            ),
        ):
            decide.return_value = WriteGateDecision(allowed=False, needs_approval=True, reason='Write requires approval.')
            return enforce_tool_call_approval(
                request,
                7,
                params=params or {},
                agent_claims=_gate_claims(),
                export_name='storage_create_bucket',
                service_id='storage',
                tool=_gate_tool(),
                method='POST',
                path='/api/v1/buckets/',
                arguments={'method': 'POST', 'path': '/api/v1/buckets/'},
            )

    def test_approved_grant_executes_once(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'approved'

        consumes = iter(
            [
                ConsumeResult(consumed=True, status_code=200),
                ConsumeResult(consumed=False, status_code=409, already_consumed=True),
            ]
        )
        first = self._run(state=state, consume=lambda *_args, **_kwargs: next(consumes))
        self.assertTrue(first.proceed)
        second = self._run(state=state, consume=lambda *_args, **_kwargs: next(consumes))
        self.assertFalse(second.proceed)
        body = json.loads(second.response.content)
        self.assertIn('expired', body['result']['content'][0]['text'].lower())
        self.assertTrue(body['result']['isError'])

    def test_url_mode_result_includes_elicitation_and_pending_shape(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        outcome = self._run(
            state=state,
            params={
                '_meta': {
                    'io.modelcontextprotocol/clientCapabilities': {'elicitation': {'url': {}}},
                }
            },
        )
        self.assertFalse(outcome.proceed)
        body = json.loads(outcome.response.content)
        result = body['result']
        self.assertFalse(result['isError'])
        self.assertNotIn('inputRequests', result)
        self.assertNotIn('resultType', result)
        self.assertEqual(result['structuredContent']['status'], 'pending')
        self.assertEqual(result['structuredContent']['approval_url'], 'https://identity.test/oauth/mcp/approval/appr-1')
        self.assertIn('human user', result['content'][0]['text'])
        self.assertIn(result['structuredContent']['approval_url'], result['content'][0]['text'])
        self.assertNotIn('\u2014', result['content'][0]['text'])

    def test_url_accept_runs_once_after_approval(self):
        calls = {'n': 0}

        def state(payload):
            calls['n'] += 1
            payload['approval_id'] = 'appr-1'
            return 'pending' if calls['n'] == 1 else 'approved'

        outcome = self._run(
            state=state,
            consume=lambda *_a, **_k: ConsumeResult(consumed=True, status_code=200),
            params={
                'inputResponses': {'approval': {'action': 'accept'}},
                '_meta': {
                    'io.modelcontextprotocol/clientCapabilities': {'elicitation': {'url': {}}},
                },
            },
        )
        self.assertTrue(outcome.proceed)
        self.assertEqual(outcome.log.get('outcome'), 'allowed')
        self.assertEqual(outcome.log.get('log_result'), 'success')

    def test_url_accept_timeout_falls_back_to_pending_result(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        outcome = self._run(
            state=state,
            params={
                'inputResponses': {'approval': {'action': 'accept'}},
                '_meta': {
                    'io.modelcontextprotocol/clientCapabilities': {'elicitation': {'url': {}}},
                },
            },
        )
        self.assertFalse(outcome.proceed)
        result = json.loads(outcome.response.content)['result']
        self.assertEqual(result['structuredContent']['status'], 'pending')
        self.assertFalse(result['isError'])

    def test_url_decline_does_not_run_the_tool(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        outcome = self._run(
            state=state,
            params={
                'inputResponses': {'approval': {'action': 'decline'}},
                '_meta': {
                    'io.modelcontextprotocol/clientCapabilities': {'elicitation': {'url': {}}},
                },
            },
        )
        self.assertFalse(outcome.proceed)
        text = json.loads(outcome.response.content)['result']['content'][0]['text']
        self.assertIn('declined', text.lower())
        self.assertIn('storage_create_bucket', text)

    def test_form_elicitation_keeps_buttons_without_url_mode(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        outcome = self._run(
            state=state,
            params={
                '_meta': {
                    'io.modelcontextprotocol/clientCapabilities': {'elicitation': {}},
                }
            },
        )
        result = json.loads(outcome.response.content)['result']
        text = result['content'][0]['text']
        self.assertIn('human user', text)
        self.assertIn('Do not open, fetch, or sign in', text)
        self.assertIn(result['structuredContent']['approval_url'], text)
        self.assertNotIn('inputRequests', result)

    def test_form_approve_records_allow_and_runs_once(self):
        from apps.connector.mcp_approval_gate import apply_elicitation_result
        from apps.connector.mcp_form_elicitation import form_elicitation_stream

        elicit = {
            'approval_id': 'appr-1',
            'approval_payload': {
                'agent_id': 'a1',
                'company_id': 10,
                'service': 'storage',
                'action': 'storage_create_bucket',
                'arguments_hash': 'h' * 64,
            },
            'connection_id': 'sess-link',
            'client_name': 'Hermes',
            'export_name': 'storage_create_bucket',
            'service_id': 'storage',
            'destructive': False,
            'agent_claims': _gate_claims(),
            'tool': _gate_tool(),
            'method': 'POST',
            'path': '/api/v1/buckets/',
        }
        with (
            patch('apps.connector.mcp_approval_gate.approvals.decide_approval') as decide,
            patch(
                'apps.connector.mcp_approval_gate.approvals.approval_consume_detail',
                return_value=ConsumeResult(consumed=True, status_code=200),
            ),
        ):
            decide.return_value = DecideResult(
                ok=True, status_code=200, audit_status='client_allowed', approval_status='approved'
            )
            stream = form_elicitation_stream(
                session_id='sess-link',
                rpc_id='eli-1',
                call_id=7,
                message='Allow storage_create_bucket? Choose Approve or Deny.',
                timeout_seconds=1,
                on_decision=lambda result: (
                    {'result': {'content': [{'type': 'text', 'text': 'ran once'}], 'isError': False}}
                    if (applied := apply_elicitation_result(7, elicit, result or {})) and applied.proceed
                    else {'result': {'content': [{'type': 'text', 'text': 'pending'}], 'isError': False}}
                ),
            )
            first = next(stream)
            from apps.connector.mcp_form_elicitation import store_elicitation_result

            self.assertIn('elicitation/create', first)
            self.assertIn('Approve', first)
            store_elicitation_result(
                'sess-link',
                'eli-1',
                {'action': 'accept', 'content': {'decision': 'approve'}},
            )
            second = next(stream)
        self.assertIn('ran once', second)
        decide.assert_called_once()
        self.assertEqual(decide.call_args.kwargs['decision'], 'allow')
        self.assertEqual(decide.call_args.kwargs['consent'], 'in_chat')
        self.assertEqual(decide.call_args.kwargs['client_name'], 'Hermes')

    def test_form_deny_does_not_run_the_tool(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        with patch('apps.connector.mcp_approval_gate.approvals.decide_approval') as decide:
            decide.return_value = DecideResult(
                ok=True, status_code=200, audit_status='client_denied', approval_status='denied'
            )
            outcome = self._run(
                state=state,
                params={
                    'inputResponses': {'approval': {'action': 'accept', 'content': {'decision': 'deny'}}},
                    '_meta': {
                        'io.modelcontextprotocol/clientCapabilities': {'elicitation': {'form': {}}},
                    },
                },
            )
        self.assertFalse(outcome.proceed)
        decide.assert_not_called()
        text = json.loads(outcome.response.content)['result']['content'][0]['text']
        self.assertIn('human user', text)

    def test_destructive_form_accept_does_not_record_in_chat_consent(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        request = self._request()
        tool = {
            'annotations': {'readOnlyHint': False, 'destructiveHint': True},
            '_meta': {'method': 'DELETE', 'path': '/api/v1/buckets/{id}/', 'destructive': True},
        }
        with (
            patch('apps.connector.mcp_approval_gate.decide_write') as decide_gate,
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', side_effect=state),
            patch('apps.connector.mcp_approval_gate.approvals.decide_approval') as decide,
            patch(
                'apps.connector.mcp_approval_gate.approvals.create_approval_request',
                return_value={'id': 'appr-1', 'status': 'pending'},
            ),
        ):
            decide_gate.return_value = WriteGateDecision(
                allowed=False, needs_approval=True, reason='Write requires approval.'
            )
            outcome = enforce_tool_call_approval(
                request,
                9,
                params={
                    'inputResponses': {
                        'approval': {'action': 'accept', 'content': {'decision': 'approve'}},
                    },
                    '_meta': {
                        'io.modelcontextprotocol/clientCapabilities': {'elicitation': {'form': {}}},
                    },
                },
                agent_claims=_gate_claims(),
                export_name='storage_delete_bucket',
                service_id='storage',
                tool=tool,
                method='DELETE',
                path='/api/v1/buckets/{id}/',
                arguments={},
            )
        decide.assert_not_called()
        self.assertFalse(outcome.proceed)
        result = json.loads(outcome.response.content)['result']
        self.assertEqual(result['structuredContent']['status'], 'pending')
        self.assertIn('approval_url', result['structuredContent'])
        self.assertNotIn('inputRequests', result)

    @override_settings(MCP_APPROVAL_CHANNEL_BY_COMPANY='{"10": "link"}')
    def test_company_override_forces_link_for_low_risk_writes(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        outcome = self._run(
            state=state,
            params={
                '_meta': {
                    'io.modelcontextprotocol/clientCapabilities': {'elicitation': {'form': {}}},
                }
            },
        )
        result = json.loads(outcome.response.content)['result']
        self.assertEqual(result['_meta']['shellui_approval']['channel'], 'link')
        self.assertIn('approval_url', result['structuredContent'])
        self.assertNotIn('inputRequests', result)

    @override_settings(MCP_APPROVAL_CHANNEL_BY_COMPANY='{"10": "form"}')
    def test_company_form_override_does_not_unlock_destructive_tools(self):
        from apps.connector.mcp_approval_channel import CHANNEL_FORM, CHANNEL_LINK, approval_channel

        self.assertEqual(
            approval_channel(destructive=True, company_id=10, form_supported=True),
            CHANNEL_LINK,
        )
        self.assertEqual(
            approval_channel(destructive=False, company_id=10, form_supported=True),
            CHANNEL_FORM,
        )
        self.assertEqual(
            approval_channel(destructive=False, company_id=11, form_supported=False),
            CHANNEL_LINK,
        )

    def test_ai_get_approval_reads_status_for_the_same_agent(self):
        def state(payload):
            payload['approval_id'] = 'appr-1'
            return 'pending'

        self._run(state=state)
        with patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=('approved', 'appr-1')):
            own = mcp_approvals.approval_status_for_agent('appr-1', _gate_claims())
        self.assertEqual(own['status'], 'approved')
        self.assertIn('same arguments', own['instruction'])
        other = mcp_approvals.approval_status_for_agent(
            'appr-1',
            {'agent_id': 'other', 'company_id': 10},
        )
        self.assertEqual(other['status'], 'unknown')
        self.assertNotIn('https://', json.dumps(other))

    def test_create_failure_message_replaces_approval_unavailable(self):
        request = self._request()

        def state(_payload):
            return None

        with (
            patch('apps.connector.mcp_approval_gate.decide_write') as decide,
            patch('apps.connector.mcp_approval_gate.approvals.session_grant_covers_write', return_value=False),
            patch('apps.connector.mcp_approval_gate.approvals.approval_state', side_effect=state),
            patch('apps.connector.mcp_approval_gate.approvals.create_approval_request', return_value=None),
            patch(
                'apps.connector.mcp_approval_gate.approvals.take_approval_create_error',
                return_value='identity_unreachable',
            ),
        ):
            decide.return_value = WriteGateDecision(allowed=False, needs_approval=True, reason='Write requires approval.')
            outcome = enforce_tool_call_approval(
                request,
                8,
                params={},
                agent_claims=_gate_claims(),
                export_name='storage_create_bucket',
                service_id='storage',
                tool=_gate_tool(),
                method='POST',
                path='/api/v1/buckets/',
                arguments={},
            )
        text = json.loads(outcome.response.content)['result']['content'][0]['text']
        self.assertNotIn('Approval unavailable.', text)
        self.assertIn('unreachable', text)
        self.assertIn('Shellui', text)
