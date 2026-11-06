"""Tests: ``forward_call_log`` matches identity-service ``develop`` internal ingest (wire POST /mcp)."""

from __future__ import annotations

from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from apps.connector import mcp_identity

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))
_SETTINGS = {
    'AI_SERVICE_SIGNING_KEY': _SIGNING,
    'AI_SERVICE_ISSUER': 'https://ai.test',
    'IDENTITY_SERVICE_URL': 'https://identity.test',
    'IDENTITY_ISSUER': 'https://identity.test',
}

_AGENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
_APPROVAL = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
_GLOBAL_CO = '11111111-1111-4111-8111-111111111111'

_CLAIMS_REGIONAL = {
    'agent_id': _AGENT,
    'company_id': 1,
    'grant_version': 2,
    'mcp_access': 'full',
    'mcp_read': 'safe',
}

_CLAIMS_DELEGATED = {
    **_CLAIMS_REGIONAL,
    'global_company_id': _GLOBAL_CO,
    'company_binding_version': 7,
}


def _base_entry(**kwargs):
    row = {
        'agent_id': _AGENT,
        'company_id': 1,
        'grant_version': 2,
        'service': 'storage',
        'tool': 'storage_list_x',
        'status': 200,
        'duration_ms': 42,
        'outcome': 'allowed',
        'access_kind': 'read',
        'log_result': 'success',
        'agent_claims': dict(_CLAIMS_REGIONAL),
    }
    row.update(kwargs)
    return row


@override_settings(**_SETTINGS)
class ForwardCallLogIdentityDevelopTests(SimpleTestCase):
    def test_wire_method_path_and_no_client_payload_noise(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(
                _base_entry(
                    method='GET',
                    path='/api/objects/foo?q=1',
                    client_ip='203.0.113.1',
                )
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['method'], 'POST')
        self.assertEqual(body['path'], '/mcp')
        self.assertNotIn('client_ip', body)
        self.assertNotIn('result', body)
        self.assertNotIn('operation_title', body)
        self.assertNotIn('arguments', body)
        self.assertNotIn('resource_label', body)
        self.assertNotIn('global_agent_id', body)

    def test_error_code_omitted_on_success(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(_base_entry())
        body = post.call_args.kwargs['json']
        self.assertNotIn('error_code', body)

    def test_error_code_on_failure(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(
                _base_entry(
                    outcome='failed',
                    status=503,
                    is_error=True,
                    error_code='upstream_error',
                    log_result='error',
                )
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['error_code'], 'upstream_error')

    def test_pending_maps_to_waiting_approval(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(
                _base_entry(
                    grant_version=0,
                    outcome='pending_approval',
                    status=202,
                    log_result='pending_approval',
                    agent_claims={**_CLAIMS_REGIONAL, 'grant_version': 0},
                )
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['outcome'], 'waiting_approval')
        self.assertEqual(body['error_code'], 'waiting_approval')

    def test_delegated_includes_global_pair(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(
                _base_entry(
                    grant_version=3,
                    global_company_id=_GLOBAL_CO,
                    company_binding_version=7,
                    agent_claims=dict(_CLAIMS_DELEGATED) | {'grant_version': 3},
                )
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['global_company_id'], _GLOBAL_CO)
        self.assertEqual(body['company_binding_version'], 7)

    def test_skips_without_matching_grant_version(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(_base_entry(grant_version=99))
        post.assert_not_called()

    def test_destructive_non_success_drops_approval_and_adds_error(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(
                _base_entry(
                    access_kind='destructive',
                    destructive_hint=True,
                    approval_id=_APPROVAL,
                    outcome='waiting_approval',
                    status=200,
                    log_result='pending_approval',
                )
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['outcome'], 'failed')
        self.assertNotIn('approval_id', body)
        self.assertEqual(body.get('error_code'), 'mcp_tool_error')

    def test_approval_id_uuid_only(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(_base_entry(approval_id='not-a-uuid'))
        body = post.call_args.kwargs['json']
        self.assertNotIn('approval_id', body)

        with patch('apps.connector.mcp_identity._http_post') as post:
            mcp_identity.forward_call_log(_base_entry(approval_id=_APPROVAL))
        body = post.call_args.kwargs['json']
        self.assertEqual(body['approval_id'], _APPROVAL)
