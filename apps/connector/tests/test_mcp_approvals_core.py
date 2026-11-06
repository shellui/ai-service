"""Unit tests for MCP approval internal calls (assertions, session grant cache)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import jwt
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from shellui_django.mcp.internal import APPROVAL_AUDIENCE

from apps.connector import mcp_approvals

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))


@override_settings(
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
    MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-approvals-core-tests',
        }
    },
)
class McpApprovalsCoreTests(TestCase):
    def setUp(self):
        cache.clear()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_assertion_includes_setup_claims_when_agent_claims_setup(self, post):
        post.return_value = MagicMock(status_code=200, json=lambda: {'id': '1', 'status': 'pending'})
        now = int(time.time())
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'x',
            'arguments_hash': 'h' * 64,
            '_agent_claims': {
                'setup_flow': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now,
                'exp': now + 900,
            },
        }
        mcp_approvals.create_approval_request(payload)
        post.assert_called_once()
        claims = jwt.decode(
            post.call_args.kwargs['headers']['Authorization'].split(' ', 1)[1],
            _SIGNING.public_pem,
            algorithms=['RS256'],
            audience=APPROVAL_AUDIENCE,
            issuer='https://ai.test',
            options={'verify_aud': True},
        )
        self.assertTrue(claims.get('setup_flow'))
        self.assertEqual(claims.get('mcp_session_ttl_seconds'), 600)
        self.assertEqual(claims['exp'] - claims['iat'], 600)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_grant_cache_key_includes_company(self, post):
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'session_allowed': True, 'expires_at': '2099-01-01T00:00:00+00:00'},
        )
        base = {
            'agent_id': 'a1',
            'service': 'storage',
            'action': 'tool',
            'arguments_hash': 'z' * 64,
        }
        now = int(time.time())
        ac = {'iat': now, 'exp': now + 3600}
        p10 = {**base, 'company_id': 10, '_agent_claims': ac}
        p99 = {**base, 'company_id': 99, '_agent_claims': ac}
        self.assertTrue(mcp_approvals.check_session_grant(p10, connection_id='conn-1', is_destructive=False))
        self.assertTrue(mcp_approvals.check_session_grant(p99, connection_id='conn-1', is_destructive=False))
        self.assertEqual(post.call_count, 2)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_grant_cache_respects_expires_at(self, post):
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'session_allowed': True, 'expires_at': '2000-01-01T00:00:01+00:00'},
        )
        now = int(time.time())
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'tool',
            'arguments_hash': 'y' * 64,
            '_agent_claims': {'iat': now, 'exp': now + 3600},
        }
        self.assertFalse(mcp_approvals.check_session_grant(payload, connection_id='c', is_destructive=False))
