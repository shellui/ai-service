"""Gateway tool calls persist one redacted row, and company admins can list them."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import Mock, patch

import requests
from django.core.cache import cache
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.authapi.principal import StoragePrincipal
from apps.connector.mcp_approvals import ConsumeResult, DecideResult
from apps.connector.mcp_call_store import (
    persist_mcp_call,
    public_status,
    redact_arguments_for_log,
    token_kind_from_claims,
)
from apps.connector.models import McpCallLog
from apps.connector.tests.test_mcp_discovery import (
    MCP_ACCEPT,
    STORAGE_TOOLS,
    _SIGNING,
    _identity_http,
    _rpc,
    _token,
)

_SETTINGS = dict(
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
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'mcp-call-log'}},
)


def _storage(post, *, call_status=200, call_error=False, raise_timeout=False):
    def side_effect(url, **kwargs):
        payload = kwargs.get('json') or {}
        if payload.get('method') == 'tools/call':
            if raise_timeout:
                raise requests.Timeout('slow')
            resp = Mock()
            resp.status_code = call_status
            if call_status >= 400:
                resp.json.side_effect = ValueError('unused')
                return resp
            resp.json.return_value = {
                'jsonrpc': '2.0',
                'id': 1,
                'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': call_error},
            }
            return resp
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = STORAGE_TOOLS
        return resp

    post.side_effect = side_effect


@override_settings(**_SETTINGS)
@patch('apps.connector.mcp_approval_gate.agent_is_revoked', return_value=False)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class GatewayCallLogTests(TestCase):
    def setUp(self):
        cache.clear()
        McpCallLog.objects.all().delete()
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
                    'params': {
                        'protocolVersion': '2025-06-18',
                        'capabilities': {'elicitation': {}},
                        'clientInfo': {'name': 'Inspector', 'version': '1'},
                    },
                }
            ),
            content_type='application/json',
            **self._auth(token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response['Mcp-Session-Id']

    def _call(self, token: str, name: str, arguments: dict | None = None, **extra):
        params = {'name': name, 'arguments': arguments or {}}
        params.update(extra)
        return self.client.post(
            '/c/10/mcp',
            data=_rpc('tools/call', **params),
            content_type='application/json',
            **self._auth(token, session_id=self._session(token)),
        )

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_direct_remote_call_writes_one_redacted_row(self, post, _mint, _http, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        response = self._call(
            token,
            'storage_list_buckets',
            {'api_key': 'sekret-value', 'name': 'Ada', 'nested': {'token': 'hide-me', 'ok': 1}},
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(response.json()['result'].get('isError'))
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.service, 'storage')
        self.assertEqual(row.tool_name, 'storage_list_buckets')
        self.assertEqual(row.wrapper_tool, '')
        self.assertEqual(row.status, 'allowed')
        self.assertEqual(row.arguments_redacted['name'], 'Ada')
        self.assertEqual(row.arguments_redacted['api_key'], '***')
        self.assertEqual(row.arguments_redacted['nested']['token'], '***')
        self.assertEqual(row.arguments_redacted['nested']['ok'], 1)
        self.assertNotIn('sekret-value', json.dumps(row.arguments_redacted))
        self.assertEqual(row.token_kind, 'agent')
        self.assertEqual(row.client_name, 'Inspector')
        self.assertEqual(row.approval_channel, 'none')

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_ai_call_tool_writes_exactly_one_row(self, post, _mint, _http, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        response = self._call(
            token,
            'ai_call_tool',
            {'name': 'storage_list_buckets', 'arguments': {'api_key': 'sekret-value', 'name': 'Ada'}},
        )
        self.assertFalse(response.json()['result'].get('isError'), response.content)
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].tool_name, 'storage_list_buckets')
        self.assertEqual(rows[0].wrapper_tool, 'ai_call_tool')
        self.assertEqual(rows[0].status, 'allowed')
        self.assertEqual(rows[0].arguments_redacted.get('api_key'), '***')
        self.assertNotIn('sekret-value', json.dumps(rows[0].arguments_redacted))

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_discovery_tools_are_logged(self, post, _mint, _http, *_mocks):
        """Lock-in: discovery tools write a row, including a failed ai_call_tool."""
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        cases = [
            ('ai_list_services', {}, 'ai_list_services', 'allowed'),
            ('ai_search_tools', {'query': 'buckets'}, 'ai_search_tools', 'allowed'),
            ('ai_describe_tool', {'name': 'storage_list_buckets'}, 'ai_describe_tool', 'allowed'),
            ('ai_get_approval', {'approval_id': 'missing'}, 'ai_get_approval', 'failed'),
            ('ai_call_tool', {}, 'ai_call_tool', 'failed'),
        ]
        for name, arguments, tool_name, status in cases:
            McpCallLog.objects.all().delete()
            response = self._call(token, name, arguments)
            self.assertEqual(response.status_code, 200, response.content)
            rows = list(McpCallLog.objects.filter(company_id=10))
            self.assertEqual(len(rows), 1, name)
            self.assertEqual(rows[0].tool_name, tool_name, name)
            self.assertEqual(rows[0].status, status, name)
            self.assertEqual(rows[0].service, 'ai', name)
            if name == 'ai_call_tool':
                self.assertEqual(rows[0].wrapper_tool, 'ai_call_tool')

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request', return_value={'id': 'appr-wait', 'status': 'pending'})
    def test_waiting_link_writes_one_row(self, _create, post, _state, _mint, _http, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        response = self._call(token, 'storage_create_bucket', {'name': 'Ada', 'password': 'sekret-value'})
        self.assertIn('appr-wait', response.content.decode())
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'waiting_approval')
        self.assertEqual(rows[0].approval_channel, 'link')
        self.assertEqual(rows[0].approval_outcome, 'pending')
        self.assertEqual(rows[0].approval_id, 'appr-wait')
        self.assertEqual(rows[0].tool_name, 'storage_create_bucket')
        self.assertEqual(rows[0].arguments_redacted.get('password'), '***')
        self.assertNotIn('sekret-value', json.dumps(rows[0].arguments_redacted))

    @override_settings(MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=90)
    @patch('apps.connector.mcp_form_elicitation.form_delivery', return_value='input_required')
    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request', return_value={'id': 'appr-form', 'status': 'pending'})
    def test_waiting_form_writes_one_row(self, _create, post, _state, _mint, _http, _delivery, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        response = self._call(token, 'storage_create_bucket', {'name': 'Ada'})
        self.assertEqual(response.status_code, 200, response.content)
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'waiting_approval')
        self.assertEqual(rows[0].approval_channel, 'form')
        self.assertEqual(rows[0].approval_id, 'appr-form')

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.approval_state', return_value='denied')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_denied_link_writes_one_row(self, post, _state, _mint, _http, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        response = self._call(
            token,
            'storage_create_bucket',
            {'name': 'Ada'},
            _meta={'shellui_approval': {'approval_id': 'appr-no'}},
        )
        self.assertIn('denied', response.json()['result']['content'][0]['text'].lower())
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'denied')
        self.assertEqual(rows[0].approval_outcome, 'denied')
        self.assertEqual(rows[0].approval_channel, 'link')

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.approval_consume_detail', return_value=ConsumeResult(consumed=True, status_code=200))
    @patch('apps.connector.mcp_approvals.approval_state')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_accepted_link_writes_one_execution_row(self, post, approval_state, _consume, _mint, _http, *_mocks):
        def _approved(payload):
            payload['approval_id'] = 'appr-yes'
            return 'approved'

        approval_state.side_effect = _approved
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        response = self._call(token, 'storage_create_bucket', {'name': 'Ada'})
        self.assertFalse(response.json()['result'].get('isError'), response.content)
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'allowed')
        self.assertEqual(rows[0].approval_outcome, 'accepted')
        self.assertEqual(rows[0].approval_channel, 'link')
        self.assertEqual(rows[0].approval_id, 'appr-yes')
        self.assertEqual(rows[0].tool_name, 'storage_create_bucket')

    @override_settings(MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=90)
    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('apps.connector.mcp_approvals.approval_consume_detail', return_value=ConsumeResult(consumed=True, status_code=200))
    @patch('apps.connector.mcp_approvals.decide_approval', return_value=DecideResult(ok=True, status_code=200, audit_status='client_allowed', approval_status='approved'))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request', return_value={'id': 'appr-form-yes', 'status': 'pending'})
    def test_accepted_form_writes_one_row(self, _create, post, _decide, _consume, _state, _mint, _http, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        response = self._call(
            token,
            'storage_create_bucket',
            {'name': 'Ada'},
            inputResponses={'approval': {'action': 'accept', 'content': {'decision': 'approve'}}},
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(response.json()['result'].get('isError'), response.content)
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'allowed')
        self.assertEqual(rows[0].approval_channel, 'form')
        self.assertEqual(rows[0].approval_outcome, 'accepted')
        self.assertEqual(rows[0].approval_id, 'appr-form-yes')

    @override_settings(MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS=90)
    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_approvals.fetch_approval_state', return_value=(None, None))
    @patch('apps.connector.mcp_approvals.decide_approval', return_value=DecideResult(ok=True, status_code=200, audit_status='client_denied', approval_status='denied'))
    @patch('shellui_django.mcp.gateway.requests.post')
    @patch('apps.connector.mcp_approvals.create_approval_request', return_value={'id': 'appr-form-no', 'status': 'pending'})
    def test_denied_form_writes_one_row(self, _create, post, _decide, _state, _mint, _http, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='ask')
        response = self._call(
            token,
            'storage_create_bucket',
            {'name': 'Ada'},
            inputResponses={'approval': {'action': 'decline', 'content': {'decision': 'deny'}}},
        )
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1, response.content)
        self.assertEqual(rows[0].status, 'denied')
        self.assertEqual(rows[0].approval_channel, 'form')
        self.assertEqual(rows[0].approval_outcome, 'denied')
        forwarded = [
            call for call in post.call_args_list if (call.kwargs.get('json') or {}).get('method') == 'tools/call'
        ]
        self.assertEqual(forwarded, [])

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('apps.connector.mcp_views.requests.post')
    def test_timeout_and_upstream_error_each_write_one_row(self, post, _mint, _http, *_mocks):
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        _storage(post, raise_timeout=True)
        timed_out = self._call(token, 'storage_list_buckets', {})
        self.assertTrue(timed_out.json()['result'].get('isError'))
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'error')
        self.assertEqual(rows[0].status_code, 504)
        self.assertEqual(rows[0].error_code, 'timeout')
        self.assertIn('timed out', rows[0].error_message.lower())

        McpCallLog.objects.all().delete()
        _storage(post, call_status=502)
        upstream = self._call(token, 'storage_list_buckets', {})
        self.assertTrue(upstream.json()['result'].get('isError'))
        rows = list(McpCallLog.objects.filter(company_id=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, 'error')
        self.assertEqual(rows[0].status_code, 502)
        self.assertEqual(rows[0].error_code, 'upstream_error')

    @patch('apps.connector.mcp_identity._http_post', side_effect=_identity_http)
    @patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token')
    @patch('shellui_django.mcp.gateway.requests.post')
    def test_log_write_failure_does_not_break_the_call(self, post, _mint, _http, *_mocks):
        _storage(post)
        token = _token(secret=self.secret, issuer=self.issuer, mcp_access='full')
        with patch('apps.connector.models.McpCallLog.objects.create', side_effect=RuntimeError('db down')):
            response = self._call(token, 'storage_list_buckets', {})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(response.json()['result'].get('isError'))
        self.assertEqual(McpCallLog.objects.count(), 0)


class CallLogHelperTests(TestCase):
    def test_redaction_and_status_mapping(self):
        redacted = redact_arguments_for_log({'name': 'Ada', 'api_key': 'sekret', 'child': [{'token': 'abc'}]})
        self.assertEqual(redacted['api_key'], '***')
        self.assertEqual(redacted['child'][0]['token'], '***')
        self.assertEqual(redacted['name'], 'Ada')
        self.assertEqual(public_status(outcome='allowed', status_code=200, error_code=''), 'allowed')
        self.assertEqual(public_status(outcome='pending_approval', status_code=202, error_code=''), 'waiting_approval')
        self.assertEqual(public_status(outcome='denied', status_code=403, error_code='denied'), 'denied')
        self.assertEqual(public_status(outcome='failed', status_code=200, error_code='mcp_tool_error'), 'failed')
        self.assertEqual(public_status(outcome='failed', status_code=504, error_code='timeout'), 'error')
        self.assertEqual(token_kind_from_claims({'personal_token_id': 'pt', 'jti': 'j'}), 'personal')
        self.assertEqual(
            token_kind_from_claims(
                {
                    'global_company_id': '11111111-1111-4111-8111-111111111111',
                    'grant_version': 1,
                    'company_binding_version': 2,
                    'personal_token_id': 'pt',
                }
            ),
            'delegated',
        )

    def test_persist_swallows_bad_rows(self):
        persist_mcp_call({'company_id': 'nope', 'tool': 'ai_list_services', 'outcome': 'allowed', 'status': 200})
        self.assertEqual(McpCallLog.objects.count(), 0)


class CallLogListApiTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.older = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-a',
            agent_name='Ada',
            service='storage',
            tool_name='storage_list_buckets',
            status='allowed',
            status_code=200,
            approval_channel='none',
        )
        self.newer = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-b',
            agent_name='Bea',
            service='ai',
            tool_name='ai_search_tools',
            wrapper_tool='',
            status='failed',
            status_code=200,
            approval_channel='none',
        )
        McpCallLog.objects.create(
            company_id=11,
            agent_id='agent-a',
            service='storage',
            tool_name='storage_list_buckets',
            status='allowed',
            status_code=200,
            approval_channel='none',
        )
        McpCallLog.objects.filter(pk=self.older.pk).update(created_at=now - timedelta(days=2))
        McpCallLog.objects.filter(pk=self.newer.pk).update(created_at=now - timedelta(hours=1))
        self.older.refresh_from_db()
        self.newer.refresh_from_db()
        self.client = APIClient()

    def _auth(self, *, company_id=10, staff=False, owner=True):
        self.client.force_authenticate(
            user=StoragePrincipal(
                user_id=7,
                company_id=company_id,
                email='owner@example.com',
                is_staff=staff,
                is_company_owner=owner,
            )
        )

    def test_company_isolation_and_filters(self):
        self._auth(company_id=10, owner=True)
        listed = self.client.get('/ai/v1/mcp/call-logs')
        self.assertEqual(listed.status_code, 200, listed.content)
        body = listed.json()
        self.assertEqual(body['count'], 2)
        self.assertEqual([row['company_id'] for row in body['call_logs']], [10, 10])
        self.assertEqual(body['call_logs'][0]['tool_name'], 'ai_search_tools')
        self.assertEqual(
            self.client.get('/ai/v1/mcp/call-logs', {'agent': 'agent-a'}).json()['count'],
            1,
        )
        self.assertEqual(
            self.client.get('/ai/v1/mcp/call-logs', {'service': 'storage'}).json()['call_logs'][0]['tool_name'],
            'storage_list_buckets',
        )
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs', {'tool': 'ai_search_tools'}).json()['count'], 1)
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs', {'status': 'failed'}).json()['count'], 1)
        after = (self.older.created_at + timedelta(hours=1)).isoformat()
        ranged = self.client.get('/ai/v1/mcp/call-logs', {'created_after': after})
        self.assertEqual(ranged.json()['count'], 1)
        self.assertEqual(ranged.json()['call_logs'][0]['agent_id'], 'agent-b')
        before = self.newer.created_at.isoformat()
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs', {'created_before': before}).json()['count'], 1)
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs', {'status': 'nope'}).status_code, 400)
        page = self.client.get('/ai/v1/mcp/call-logs', {'limit': 1, 'offset': 1})
        self.assertEqual(page.json()['count'], 2)
        self.assertEqual(len(page.json()['call_logs']), 1)
        self.assertEqual(page.json()['call_logs'][0]['agent_id'], 'agent-a')

        self._auth(company_id=11, owner=True)
        other = self.client.get('/ai/v1/mcp/call-logs')
        self.assertEqual(other.json()['count'], 1)
        self.assertEqual(other.json()['call_logs'][0]['company_id'], 11)

    def test_staff_can_list_own_company_and_members_cannot(self):
        self._auth(company_id=10, staff=True, owner=False)
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs').status_code, 200)
        self._auth(company_id=10, staff=False, owner=False)
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs').status_code, 403)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs').status_code, 401)

    def test_prune_keeps_rows_inside_the_window(self):
        McpCallLog.objects.filter(pk=self.older.pk).update(created_at=timezone.now() - timedelta(days=91))
        call_command('prune_mcp_call_logs', days=90)
        self.assertFalse(McpCallLog.objects.filter(pk=self.older.pk).exists())
        self.assertTrue(McpCallLog.objects.filter(pk=self.newer.pk).exists())
        self.assertTrue(McpCallLog.objects.filter(company_id=11).exists())
