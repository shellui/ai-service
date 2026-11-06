"""Unit tests for MCP approval internal calls (assertions, session-check)."""

from __future__ import annotations

import time
import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

import jwt
from django.test import TestCase, override_settings
from django.utils import timezone

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

_GV = 1
_CBV = 1
_GLOBAL_CO = '11111111-1111-4111-8111-111111111111'


def _claims_base(now: int) -> dict:
    return {
        'iat': now,
        'exp': now + 3600,
        'grant_version': _GV,
        'company_binding_version': _CBV,
        'global_company_id': _GLOBAL_CO,
    }


def _session_ok_response(*, expires_at: str | None, setup_expires_at: str | None = None):
    body: dict = {
        'session_allowed': True,
        'grant_version': int(_GV),
        'company_binding_version': int(_CBV),
    }
    if expires_at is not None:
        body['expires_at'] = expires_at
    if setup_expires_at is not None:
        body['setup_expires_at'] = setup_expires_at
    return MagicMock(status_code=200, json=lambda b=body: b)


@override_settings(
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
    MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
)
class McpApprovalsCoreTests(TestCase):
    def setUp(self):
        revoke = patch('apps.connector.mcp_approvals.agent_is_revoked', return_value=False)
        revoke.start()
        self.addCleanup(revoke.stop)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_assertion_includes_setup_claims_when_agent_claims_setup(self, post):
        post.return_value = MagicMock(status_code=200, json=lambda: {'id': '1', 'status': 'pending'})
        now = int(time.time())
        setup_exp = timezone.now() + timedelta(seconds=650)
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'x',
            'arguments_hash': 'h' * 64,
            '_agent_claims': {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': setup_exp.isoformat(),
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
        self.assertEqual(claims.get('grant_version'), _GV)
        self.assertEqual(claims.get('company_binding_version'), _CBV)
        self.assertEqual(claims.get('global_company_id'), _GLOBAL_CO)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_check_called_every_time_no_cache(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut)
        base = {
            'agent_id': 'a1',
            'service': 'storage',
            'action': 'tool',
            'arguments_hash': 'z' * 64,
        }
        now = int(time.time())
        ac = _claims_base(now)
        p10 = {**base, 'company_id': 10, '_agent_claims': ac}
        p99 = {**base, 'company_id': 99, '_agent_claims': ac}
        self.assertTrue(mcp_approvals.check_session_grant(p10, connection_id='conn-1', is_destructive=False))
        self.assertTrue(mcp_approvals.check_session_grant(p99, connection_id='conn-1', is_destructive=False))
        self.assertEqual(post.call_count, 2)
        for call in post.call_args_list:
            jb = call.kwargs.get('json') or {}
            self.assertEqual(jb.get('grant_version'), int(_GV))
            self.assertEqual(jb.get('company_binding_version'), int(_CBV))
            self.assertEqual(jb.get('global_company_id'), _GLOBAL_CO)
            self.assertEqual(jb.get('arguments_hash'), 'z' * 64)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_rejects_past_expires_at(self, post):
        post.return_value = _session_ok_response(expires_at='2000-01-01T00:00:01+00:00')
        now = int(time.time())
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'tool',
            'arguments_hash': 'y' * 64,
            '_agent_claims': _claims_base(now),
        }
        self.assertFalse(mcp_approvals.check_session_grant(payload, connection_id='c', is_destructive=False))

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_second_call_still_hits_identity(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut)
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': _claims_base(now)}
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='conn-x', is_destructive=False))
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='conn-x', is_destructive=False))
        self.assertEqual(post.call_count, 2)

    @patch('apps.connector.mcp_approvals.agent_is_revoked')
    @patch('apps.connector.mcp_approvals.requests.post')
    def test_revoked_agent_rejected_after_identity_ok(self, post, revoked):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut)
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': _claims_base(now)}
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
            '_agent_claims': _claims_base(now),
        }
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='cx', is_destructive=False))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_grant_version_mismatch_rejected_when_session_not_ordinary(self, post):
        """Beyond the ~60s ordinary window, delegated session must match current identity versions."""
        fut = (timezone.now() + timedelta(seconds=120)).isoformat()

        def _json():
            return {
                'session_allowed': True,
                'grant_version': 99999,
                'company_binding_version': _CBV,
                'expires_at': fut,
            }

        post.return_value = MagicMock(status_code=200, json=_json)
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': _claims_base(now)}
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='c-mv', is_destructive=False))
        post.assert_called_once()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_grant_version_mismatch_grandfathered_ordinary_session(self, post):
        """Pre-existing ordinary (~60s) grant stays valid while JWT exp remains absolute cap."""
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()

        def _json():
            return {
                'session_allowed': True,
                'grant_version': 99999,
                'company_binding_version': _CBV,
                'expires_at': fut,
            }

        post.return_value = MagicMock(status_code=200, json=_json)
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': _claims_base(now)}
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='c-mv-gf', is_destructive=False))
        post.assert_called_once()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_missing_versions_in_token_rejected(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut)
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {'iat': now, 'exp': now + 3600},
        }
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='c-mv', is_destructive=False))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_integer_zero_versions_match_string_response(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = MagicMock(
            status_code=200,
            json=lambda b=fut: {
                'session_allowed': True,
                'grant_version': 0,
                'company_binding_version': 0,
                'expires_at': b,
            },
        )
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'iat': now,
                'exp': now + 3600,
                'grant_version': 0,
                'company_binding_version': 0,
                'global_company_id': _GLOBAL_CO,
            },
        }
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='cz', is_destructive=False))
        jb = post.call_args.kwargs.get('json') or {}
        self.assertEqual(jb.get('grant_version'), 0)
        self.assertEqual(jb.get('company_binding_version'), 0)
        self.assertEqual(jb.get('global_company_id'), _GLOBAL_CO)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_personal_omits_version_keys_when_absent_on_token(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = MagicMock(status_code=200, json=lambda: {'session_allowed': True, 'expires_at': fut})
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'iat': now,
                'exp': now + 3600,
                'personal_token_id': 'pt-1',
                'jti': 'jt-1',
            },
        }
        self.assertTrue(mcp_approvals.check_session_grant(p, connection_id='cp', is_destructive=False))
        jb = post.call_args.kwargs.get('json') or {}
        self.assertNotIn('grant_version', jb)
        self.assertNotIn('company_binding_version', jb)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_personal_one_version_without_other_rejected(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut)
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'iat': now,
                'exp': now + 3600,
                'personal_token_id': 'pt-1',
                'jti': 'jt-1',
                'grant_version': _GV,
            },
        }
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='c1v', is_destructive=False))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_assertion_jwt_includes_integer_zero_versions(self, post):
        post.return_value = MagicMock(status_code=200, json=lambda: {'id': '1', 'status': 'pending'})
        now = int(time.time())
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'x',
            'arguments_hash': 'h' * 64,
            '_agent_claims': {
                'iat': now,
                'exp': now + 3600,
                'grant_version': 0,
                'company_binding_version': 0,
                'global_company_id': _GLOBAL_CO,
            },
        }
        mcp_approvals.create_approval_request(payload)
        post.assert_called_once()
        token = post.call_args.kwargs['headers']['Authorization'].split(' ', 1)[1]
        claims = jwt.decode(
            token,
            _SIGNING.public_pem,
            algorithms=['RS256'],
            audience=APPROVAL_AUDIENCE,
            issuer='https://ai.test',
            options={'verify_aud': True},
        )
        self.assertEqual(claims.get('grant_version'), 0)
        self.assertEqual(claims.get('company_binding_version'), 0)
        self.assertEqual(claims.get('global_company_id'), _GLOBAL_CO)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_create_skips_when_delegated_setup_claim_invalid(self, post):
        now = int(time.time())
        setup_exp = timezone.now() + timedelta(seconds=650)
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'x',
            'arguments_hash': 'h' * 64,
            '_agent_claims': {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': setup_exp.isoformat(),
                'iat': now - 3600,
                'exp': now + 30,
            },
        }
        self.assertIsNone(mcp_approvals.create_approval_request(payload))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_delegated_missing_global_company_id_rejected(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut)
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'iat': now,
                'exp': now + 3600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
            },
        }
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='c-gc', is_destructive=False))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_delegated_string_grant_version_rejected(self, post):
        fut = (timezone.now() + timedelta(seconds=30)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut)
        now = int(time.time())
        p = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'iat': now,
                'exp': now + 3600,
                'grant_version': 'not-an-int',
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
            },
        }
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='c-sv', is_destructive=False))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_session_allowed_boolean_alone_insufficient(self, post):
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'session_allowed': True},
        )
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': _claims_base(now)}
        self.assertFalse(mcp_approvals.check_session_grant(p, connection_id='c-sa', is_destructive=False))
        post.assert_called_once()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_revoke_session_posts_identity(self, post):
        post.return_value = MagicMock(status_code=200, json=lambda: {'revoked': True})
        now = int(time.time())
        p = {**_BASE_PAYLOAD, '_agent_claims': _claims_base(now)}
        self.assertTrue(mcp_approvals.revoke_session_grant(p, connection_id='r1'))
        post.assert_called_once()


@override_settings(
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
    MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
)
class McpSessionGrantSetupFlowTests(TestCase):
    def setUp(self):
        revoke = patch('apps.connector.mcp_approvals.agent_is_revoked', return_value=False)
        revoke.start()
        self.addCleanup(revoke.stop)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_setup_requires_setup_expires_at_on_response(self, post):
        fut = (timezone.now() + timedelta(seconds=700)).isoformat()
        post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                'session_allowed': True,
                'grant_version': int(_GV),
                'company_binding_version': int(_CBV),
                'expires_at': fut,
            },
        )
        now = int(time.time())
        setup_exp = timezone.now() + timedelta(seconds=650)
        payload = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': setup_exp.isoformat(),
                'iat': now,
                'exp': now + 900,
            },
        }
        self.assertFalse(mcp_approvals.check_session_grant(payload, connection_id='c-setup', is_destructive=False))
        post.assert_called_once()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_setup_accepted_with_matching_versions_and_setup_expires_at(self, post):
        fut = (timezone.now() + timedelta(seconds=700)).isoformat()
        setup_resp = (timezone.now() + timedelta(seconds=680)).isoformat()
        post.return_value = _session_ok_response(expires_at=fut, setup_expires_at=setup_resp)
        now = int(time.time())
        setup_claim = timezone.now() + timedelta(seconds=690)
        payload = {
            **_BASE_PAYLOAD,
            '_agent_claims': {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': setup_claim.isoformat(),
                'iat': now,
                'exp': now + 900,
            },
        }
        self.assertTrue(mcp_approvals.check_session_grant(payload, connection_id='c-ok', is_destructive=False))
