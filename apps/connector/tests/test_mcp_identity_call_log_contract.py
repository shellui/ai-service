"""Tests: ``forward_call_log`` matches identity-service ``develop`` ``McpInternalCallLogView``."""

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


@override_settings(**_SETTINGS)
class ForwardCallLogIdentityDevelopTests(SimpleTestCase):
    def test_body_matches_internal_call_log_view(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': _AGENT,
                    'company_id': 1,
                    'grant_version': 2,
                    'service': 'storage',
                    'tool': 'storage_list_x',
                    'method': 'GET',
                    'path': '/api/r?q=1',
                    'status': 200,
                    'client_ip': '203.0.113.1',
                    'duration_ms': 42,
                    'outcome': 'allowed',
                    'access_kind': 'read',
                    'log_result': 'success',
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(
            set(body.keys()),
            {
                'agent_id',
                'company_id',
                'grant_version',
                'service',
                'tool',
                'method',
                'path',
                'status',
                'duration_ms',
                'client_ip',
                'result',
                'outcome',
                'access_kind',
                'error_code',
            },
        )
        self.assertEqual(body['outcome'], 'allowed')
        self.assertEqual(body['result'], 'success')
        self.assertEqual(body['path'], '/api/r')
        self.assertEqual(body['error_code'], '')
        self.assertNotIn('operation_title', body)
        self.assertNotIn('arguments', body)
        self.assertNotIn('resource_label', body)

    def test_pending_maps_to_waiting_approval_outcome(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': _AGENT,
                    'company_id': 1,
                    'grant_version': 0,
                    'method': 'GET',
                    'path': '/api/r?q=1',
                    'status': 202,
                    'outcome': 'pending_approval',
                    'access_kind': 'read',
                    'log_result': 'pending_approval',
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['outcome'], 'waiting_approval')
        self.assertEqual(body['result'], 'pending_approval')

    def test_delegated_includes_global_binding(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': _AGENT,
                    'company_id': 1,
                    'grant_version': 3,
                    'global_company_id': _GLOBAL_CO,
                    'company_binding_version': 7,
                    'method': 'GET',
                    'status': 200,
                    'outcome': 'allowed',
                    'access_kind': 'read',
                    'log_result': 'success',
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['global_company_id'], _GLOBAL_CO)
        self.assertEqual(body['company_binding_version'], 7)
        self.assertEqual(body['grant_version'], 3)

    def test_approval_id_only_when_uuid(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': _AGENT,
                    'company_id': 1,
                    'grant_version': 1,
                    'method': 'GET',
                    'status': 200,
                    'outcome': 'allowed',
                    'access_kind': 'read',
                    'approval_id': 'not-a-uuid',
                }
            )
        body = post.call_args.kwargs['json']
        self.assertNotIn('approval_id', body)

        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': _AGENT,
                    'company_id': 1,
                    'grant_version': 1,
                    'method': 'GET',
                    'status': 200,
                    'outcome': 'allowed',
                    'access_kind': 'read',
                    'approval_id': _APPROVAL,
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['approval_id'], _APPROVAL)
