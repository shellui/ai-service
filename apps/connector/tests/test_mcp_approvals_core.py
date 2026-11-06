"""Unit tests for MCP approval internal calls (assertions, session grant cache)."""

from __future__ import annotations

import time
import uuid
from unittest.mock import MagicMock, patch

import jwt
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from shellui_django.mcp.internal import APPROVAL_AUDIENCE

from apps.connector import mcp_approvals

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))

_BASE_PAYLOAD = {
    'agent_id': 'a1',
    'company_id': 10,
    'service': 'storage',
    'action': 'tool',
    'arguments_hash': 'y' * 64,
}


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
        revoke = patch('apps.connector.mcp_approvals.agent_is_revoked', return_value=False)
        revoke.start()
        self.addCleanup(revoke.stop)
        rf = patch('apps.connector.mcp_approvals.revocation_list_fingerprint', return_value='test-fp')
        rf.start()
        self.addCleanup(rf.stop)

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
                'company_id': 10,
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
            json=lambda: {
                'session_allowed': True,
                'expires_at': '2099-01-01T00:00:00+00:00',
                'grant_validity_version': 'v-test',
            },
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
            json=lambda: {
                'session_allowed': True,
                'expires_at': '2000-01-01T00:00:01+00:00',
                'grant_validity_version': 'v-test',
            },
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

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_grant_cache_invalidated_on_revocation_fingerprint_change(self, post):
        fut = '2099-01-01T00:00:00+00:00'
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'session_allowed': True, 'expires_at': fut, 'grant_validity_version': 'v-test'},
        )
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {'iat': now, 'exp': now + 3600, 'jti': 'tok-1'},
        }
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='conn-x', is_destructive=False))
        post.assert_called_once()
        with patch('apps.connector.mcp_approvals.revocation_list_fingerprint', return_value='fp-b'):
            self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='conn-x', is_destructive=False))
        self.assertEqual(post.call_count, 2)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_grant_cache_requires_matching_jti(self, post):
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                'session_allowed': True,
                'expires_at': '2099-01-01T00:00:00+00:00',
                'grant_validity_version': 'v-test',
            },
        )
        now = int(time.time())
        p1 = {**_BASE_PAYLOAD, '_agent_claims': {'iat': now, 'exp': now + 3600, 'jti': 'aa'}}
        self.assertTrue(mcp_approvals.check_session_grant(p1, connection_id='c', is_destructive=False))
        p2 = {**_BASE_PAYLOAD, '_agent_claims': {'iat': now, 'exp': now + 3600, 'jti': 'bb'}}
        self.assertTrue(mcp_approvals.check_session_grant(p2, connection_id='c', is_destructive=False))
        self.assertEqual(post.call_count, 2)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_grant_cached_expiry_capped_by_access_token_wall_time(self, post):
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                'session_allowed': True,
                'expires_at': '2099-01-01T00:00:00+00:00',
                'grant_validity_version': 'v-test',
            },
        )
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {'iat': now, 'exp': now + 45, 'jti': 'wall-cap', 'grant_validity_version': 'v-test'},
        }
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='c2', is_destructive=False))
        post.assert_called_once()
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='c2', is_destructive=False))
        self.assertEqual(post.call_count, 1)
        mk = mcp_approvals._grant_map_key(connection_id='c2', agent_id='a1', company_id=10)
        raw = cache.get(mk)
        self.assertIsInstance(raw, dict)
        rec = next(iter(raw.values()))
        self.assertLessEqual(rec['exp_ms'], mcp_approvals._now_ms() + 50_000)

    @patch('apps.connector.mcp_approvals.agent_is_revoked')
    @patch('apps.connector.mcp_approvals.requests.post')
    def test_revoked_agent_cannot_use_positive_cache(self, post, revoked):
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                'session_allowed': True,
                'expires_at': '2099-01-01T00:00:00+00:00',
                'grant_validity_version': 'v-test',
            },
        )
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': {'iat': now, 'exp': now + 3600, 'jti': 'rvk'}}
        revoked.return_value = False
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='c3', is_destructive=False))
        revoked.return_value = True
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='c3', is_destructive=False))

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_invalid_company_id_uuid_rejected_before_identity(self, post):
        now = int(time.time())
        p = {
            'agent_id': 'a1',
            'company_id': str(uuid.uuid4()),
            'service': 'storage',
            'action': 'tool',
            'arguments_hash': 'y' * 64,
            '_agent_claims': {'iat': now, 'exp': now + 3600, 'jti': 'x'},
        }
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='cx', is_destructive=False))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_grant_cache_invalidated_on_grant_version_change(self, post):
        fut = '2099-01-01T00:00:00+00:00'

        def _resp(version: str):
            return MagicMock(
                status_code=200,
                json=lambda v=version: {
                    'session_allowed': True,
                    'expires_at': fut,
                    'grant_validity_version': v,
                },
            )

        post.side_effect = [_resp('v1'), _resp('v2')]
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': {'iat': now, 'exp': now + 3600, 'jti': 'gv'}}
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='c-gv', is_destructive=False))
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='c-gv', is_destructive=False))
        self.assertEqual(post.call_count, 2)


@override_settings(
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
    MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
    MCP_SESSION_GRANT_REQUIRES_ABSOLUTE_EXPIRES_AT=True,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-approvals-core-tests-abs',
        }
    },
)
class McpSessionGrantAbsoluteExpiryTests(TestCase):
    def setUp(self):
        cache.clear()
        revoke = patch('apps.connector.mcp_approvals.agent_is_revoked', return_value=False)
        revoke.start()
        self.addCleanup(revoke.stop)
        rf = patch('apps.connector.mcp_approvals.revocation_list_fingerprint', return_value='test-fp')
        rf.start()
        self.addCleanup(rf.stop)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_setup_flow_rejects_session_check_without_absolute_expires_at(self, post):
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'session_allowed': True, 'grant_validity_version': 'v-abs'},
        )
        now = int(time.time())
        payload = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'company_id': 10,
                'setup_flow': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now,
                'exp': now + 900,
                'jti': 'abs-1',
            },
        }
        self.assertFalse(mcp_approvals.check_session_grant(payload, connection_id='c-abs', is_destructive=False))
        post.assert_called_once()
