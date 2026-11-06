"""Tests: ``forward_call_log`` matches identity-service PR #136 trusted allowlist."""

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


@override_settings(**_SETTINGS)
class ForwardCallLogIdentity136Tests(SimpleTestCase):
    def test_body_is_allowlisted_with_operation_result(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'company_id': 1,
                    'service': 'storage',
                    'tool': 'storage_list_x',
                    'method': 'GET',
                    'path': '/api/r?q=1',
                    'status': 200,
                    'client_ip': '203.0.113.1',
                    'duration_ms': 42,
                    'outcome': 'allowed',
                    'access_kind': 'read',
                    'operation_title': 'List objects',
                    'resource_label': 'GET-/api/v1/buckets/',
                    'log_result': 'success',
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(set(body.keys()), {
            'agent_id',
            'company_id',
            'service',
            'tool',
            'method',
            'path',
            'status',
            'duration_ms',
            'client_ip',
            'arguments',
            'operation_title',
            'access_kind',
            'operation_result',
            'resource_label',
        })
        self.assertEqual(body['arguments'], {})
        self.assertEqual(body['operation_result'], 'success')
        self.assertEqual(body['path'], '/api/r')

    def test_pending_maps_to_unavailable_operation_result(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'company_id': 1,
                    'method': 'GET',
                    'status': 202,
                    'outcome': 'pending_approval',
                    'operation_title': 'Op',
                    'resource_label': 'gateway:t',
                    'access_kind': 'read',
                    'log_result': 'pending_approval',
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['operation_result'], 'unavailable')

    def test_approval_request_id_only_when_uuid(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'company_id': 1,
                    'method': 'GET',
                    'status': 200,
                    'outcome': 'allowed',
                    'operation_title': 'Op',
                    'resource_label': 'gateway:t',
                    'access_kind': 'read',
                    'approval_id': 'not-a-uuid',
                }
            )
        body = post.call_args.kwargs['json']
        self.assertNotIn('approval_request_id', body)

        with patch('apps.connector.mcp_identity.requests.post') as post:
            aid = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
            mcp_identity.forward_call_log(
                {
                    'agent_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'company_id': 1,
                    'method': 'GET',
                    'status': 200,
                    'outcome': 'allowed',
                    'operation_title': 'Op',
                    'resource_label': 'gateway:t',
                    'access_kind': 'read',
                    'approval_id': aid,
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['approval_request_id'], aid)
