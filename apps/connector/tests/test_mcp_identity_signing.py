"""Internal assertions to Identity are RS256, signed with the ai-service key."""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from shellui_django.mcp.internal import (
    CALL_LOG_AUDIENCE,
    CALL_LOG_SCOPE,
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

    def test_call_log_is_signed_with_ai_service_key(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log({'agent_id': 'a', 'company_id': 1})
        self._verify(_bearer(post.call_args), audience=CALL_LOG_AUDIENCE, scope=CALL_LOG_SCOPE)

    @override_settings(AI_SERVICE_SIGNING_KEY=None)
    def test_without_signing_key_revocation_fails_closed(self):
        with patch('apps.connector.mcp_identity.requests.get') as get:
            self.assertTrue(mcp_identity.agent_is_revoked('agent-1', 1))
        get.assert_not_called()

    @override_settings(AI_SERVICE_SIGNING_KEY=None)
    def test_without_signing_key_call_log_is_skipped(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log({'agent_id': 'a', 'company_id': 1})
        post.assert_not_called()
