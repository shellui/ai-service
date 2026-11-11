"""Internal assertions to Identity are RS256, signed with the ai-service key."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from shellui_django.mcp.internal import (
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    verify_mcp_internal_assertion,
)

from apps.authapi.ai_service_jwks import (
    build_jwks_document,
    compute_rsa_kid,
    generate_rsa_key_pair,
    load_ai_service_signing_key,
)
from apps.connector import mcp_identity
from apps.connector.mcp_identity import DELEGATED_AGENT_AUTHORITY_AUDIENCE, DELEGATED_AGENT_AUTHORITY_SCOPE

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))
_SETTINGS = {
    'AI_SERVICE_SIGNING_KEY': _SIGNING,
    'AI_SERVICE_ISSUER': 'https://ai.test',
    'IDENTITY_SERVICE_URL': 'https://identity.test',
    'IDENTITY_ISSUER': 'https://identity.test',
}


def _bearer(call) -> str:
    return call.kwargs['headers']['Authorization'].removeprefix('Bearer ')


@override_settings(**_SETTINGS)
class McpIdentitySigningTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def _verify(self, token: str, *, audience: str, scope: str) -> dict:
        return verify_mcp_internal_assertion(
            token,
            build_jwks_document(_SIGNING),
            expected_issuer='https://ai.test',
            expected_audience=audience,
            expected_scope=scope,
            expected_target='https://identity.test',
        )

    def test_revocation_poll_is_signed_with_ai_service_key(self):
        with patch('apps.connector.mcp_identity.requests.get') as get:
            get.return_value.status_code = 503
            mcp_identity._refresh_revocations()
        claims = self._verify(_bearer(get.call_args), audience=REVOCATION_AUDIENCE, scope=REVOCATION_SCOPE)
        self.assertEqual(claims['iss'], 'https://ai.test')

    def _delegated_ok_json(self, **overrides):
        """Minimal valid **200** body matching identity ``d7fe351`` ``_delegated_authority_fixed_payload`` (15 keys)."""
        base = {
            'authorized': True,
            'active': True,
            'revoked': False,
            'paused': False,
            'agent_id': '11111111-1111-4111-8111-111111111111',
            'company_id': 10,
            'global_agent_id': '33333333-3333-4333-8333-333333333333',
            'global_company_id': '22222222-2222-4222-8222-222222222222',
            'grant_version': 1,
            'company_binding_version': 2,
            'access_mode': 'read',
            'read_level': 'full',
            'allow_destructive': False,
            'services_allowed': ['ai', 'storage'],
            'revoked_at': None,
        }
        base.update(overrides)
        return base

    def test_delegated_authority_internal_assertion_shape(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            post.return_value = MagicMock(
                status_code=200,
                json=lambda: self._delegated_ok_json(),
            )
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
                agent_claims={
                    'scope': 'storage ai',
                    'mcp_access': 'read',
                    'mcp_read': 'full',
                    'global_agent_id': '33333333-3333-4333-8333-333333333333',
                    'grant_version': 1,
                    'company_binding_version': 2,
                    'global_company_id': '22222222-2222-4222-8222-222222222222',
                    'mcp_destructive': False,
                },
            )
        self.assertTrue(ok)
        claims = self._verify(
            _bearer(post.call_args),
            audience=DELEGATED_AGENT_AUTHORITY_AUDIENCE,
            scope=DELEGATED_AGENT_AUTHORITY_SCOPE,
        )
        self.assertEqual(claims.get('sub'), 'service')

    def test_delegated_authority_rejects_global_company_echo_mismatch(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            bad = self._delegated_ok_json(
                authorized=False,
                active=False,
                global_company_id='33333333-3333-4333-8333-333333333333',
            )
            post.return_value = MagicMock(status_code=200, json=lambda: bad)
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
            )
        self.assertFalse(ok)

    def test_delegated_authority_rejects_string_grant_version_in_json(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            bad = self._delegated_ok_json(grant_version='1')
            post.return_value = MagicMock(status_code=200, json=lambda: bad)
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
            )
        self.assertFalse(ok)

    def test_delegated_authority_requires_exactly_15_keys(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            bad = self._delegated_ok_json()
            bad['extra'] = 'nope'
            post.return_value = MagicMock(status_code=200, json=lambda: bad)
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
            )
        self.assertFalse(ok)

    def test_delegated_authority_rejects_services_scope_mismatch(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            post.return_value = MagicMock(
                status_code=200,
                json=lambda: self._delegated_ok_json(services_allowed=['ai']),
            )
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
                agent_claims={
                    'scope': 'ai storage',
                    'grant_version': 1,
                    'company_binding_version': 2,
                    'global_company_id': '22222222-2222-4222-8222-222222222222',
                    'global_agent_id': '33333333-3333-4333-8333-333333333333',
                    'mcp_destructive': False,
                },
            )
        self.assertFalse(ok)

    def test_delegated_authority_requires_global_agent_id_on_delegated_claims(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            post.return_value = MagicMock(status_code=200, json=lambda: self._delegated_ok_json())
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
                agent_claims={
                    'scope': 'ai storage',
                    'mcp_access': 'read',
                    'mcp_read': 'full',
                    'grant_version': 1,
                    'company_binding_version': 2,
                    'global_company_id': '22222222-2222-4222-8222-222222222222',
                    'mcp_destructive': False,
                },
            )
        self.assertFalse(ok)

    def test_delegated_authority_requires_bool_mcp_destructive(self):
        with patch('apps.connector.mcp_identity._http_post') as post:
            post.return_value = MagicMock(status_code=200, json=lambda: self._delegated_ok_json())
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
                agent_claims={
                    'scope': 'ai storage',
                    'mcp_access': 'read',
                    'mcp_read': 'full',
                    'global_agent_id': '33333333-3333-4333-8333-333333333333',
                    'grant_version': 1,
                    'company_binding_version': 2,
                    'global_company_id': '22222222-2222-4222-8222-222222222222',
                    'mcp_destructive': 'false',
                },
            )
        self.assertFalse(ok)

    @override_settings(AI_SERVICE_SIGNING_KEY=None)
    def test_without_signing_key_revocation_fails_closed(self):
        with patch('apps.connector.mcp_identity.requests.get') as get:
            self.assertTrue(mcp_identity.agent_is_revoked('agent-1', 1))
        get.assert_not_called()

