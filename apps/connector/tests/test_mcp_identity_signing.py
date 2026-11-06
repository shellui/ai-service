"""Internal assertions to Identity are RS256, signed with the ai-service key."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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

    def test_call_log_is_signed_with_ai_service_key(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': 'a',
                    'company_id': 1,
                    'method': 'POST',
                    'status': 200,
                    'client_ip': '203.0.113.1',
                    'result': 'success',
                    'duration_ms': 42,
                }
            )
        self._verify(_bearer(post.call_args), audience=CALL_LOG_AUDIENCE, scope=CALL_LOG_SCOPE)
        body = post.call_args.kwargs['json']
        self.assertEqual(body['method'], 'POST')
        self.assertEqual(body['client_ip'], '203.0.113.1')
        self.assertEqual(body['result'], 'success')
        self.assertEqual(body['duration_ms'], 42)
        self.assertNotIn('arguments', body)
        self.assertNotIn('arguments_redacted', body)

    def test_call_log_pending_outcome_maps_for_identity(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log(
                {
                    'agent_id': 'a',
                    'company_id': 1,
                    'method': 'GET',
                    'path': '/api/r?q=1',
                    'outcome': 'pending',
                    'result': 'pending',
                    'status': 202,
                }
            )
        body = post.call_args.kwargs['json']
        self.assertEqual(body['outcome'], 'pending_approval')
        self.assertEqual(body['path'], '/api/r')
        self.assertEqual(body['result'], 'pending_approval')

    def _delegated_ok_json(
        self,
        *,
        agent_id='11111111-1111-4111-8111-111111111111',
        company_id=10,
        global_company_id='22222222-2222-4222-8222-222222222222',
        grant_version=1,
        company_binding_version=2,
    ):
        return {
            'authorized': True,
            'revoked': False,
            'paused': False,
            'agent_id': agent_id,
            'company_id': company_id,
            'global_company_id': global_company_id,
            'grant_version': grant_version,
            'company_binding_version': company_binding_version,
        }

    def test_delegated_authority_internal_assertion_shape(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
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
            )
        self.assertTrue(ok)
        claims = self._verify(
            _bearer(post.call_args),
            audience=DELEGATED_AGENT_AUTHORITY_AUDIENCE,
            scope=DELEGATED_AGENT_AUTHORITY_SCOPE,
        )
        self.assertEqual(claims.get('sub'), 'service')

    def test_delegated_authority_rejects_global_company_echo_mismatch(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            bad = self._delegated_ok_json(global_company_id='33333333-3333-4333-8333-333333333333')
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
        with patch('apps.connector.mcp_identity.requests.post') as post:
            bad = self._delegated_ok_json()
            bad['grant_version'] = '1'
            post.return_value = MagicMock(status_code=200, json=lambda: bad)
            ok = mcp_identity.verify_live_delegated_agent_authority(
                agent_id='11111111-1111-4111-8111-111111111111',
                company_id=10,
                global_company_id='22222222-2222-4222-8222-222222222222',
                grant_version=1,
                company_binding_version=2,
            )
        self.assertFalse(ok)

    @override_settings(AI_SERVICE_SIGNING_KEY=None)
    def test_without_signing_key_revocation_fails_closed(self):
        with patch('apps.connector.mcp_identity.requests.get') as get:
            self.assertTrue(mcp_identity.agent_is_revoked('agent-1', 1))
        get.assert_not_called()

    @override_settings(AI_SERVICE_SIGNING_KEY=None)
    def test_without_signing_key_call_log_is_not_sent(self):
        with patch('apps.connector.mcp_identity.requests.post') as post:
            mcp_identity.forward_call_log({'agent_id': 'a', 'company_id': 1})
        post.assert_not_called()
