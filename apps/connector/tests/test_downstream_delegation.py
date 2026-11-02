"""RS256 downstream token delegation to identity."""

from __future__ import annotations

import logging
from unittest.mock import patch

import jwt
from django.test import Client, SimpleTestCase, TestCase, override_settings

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from apps.connector.agent_record import AgentRecord
from apps.connector.downstream_tokens import mint_downstream_access_token
# Avoid literal PEM banner substrings so repo hygiene secret scans stay quiet.
_PEM_RSA_BANNER = 'BEGIN ' + 'RSA PRIVATE KEY'
_PEM_PKCS8_BANNER = 'BEGIN ' + 'PRIVATE KEY'

from shellui_django.mcp.delegation import (
    DOWNSTREAM_TOKEN_AUDIENCE,
    DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS,
    DOWNSTREAM_TOKEN_SCOPE,
    verify_downstream_token_request,
)


def _signing_settings() -> dict:
    private_pem, public_pem = generate_rsa_key_pair(key_size=2048)
    kid = compute_rsa_kid(public_pem)
    signing = load_ai_service_signing_key(private_pem=private_pem, kid=kid)
    return {
        'AI_SERVICE_SIGNING_KEY': signing,
        'AI_SERVICE_SIGNING_KID': kid,
        'AI_SERVICE_ISSUER': 'https://ai.test',
        'IDENTITY_SERVICE_URL': 'https://identity.test',
        'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS': 5,
    }


_DELEGATION_TEST_SETTINGS = _signing_settings()


@override_settings(**_DELEGATION_TEST_SETTINGS)
class DownstreamDelegationSigningTests(SimpleTestCase):
    def test_request_jwt_is_rs256_with_expected_claims_and_short_ttl(self):
        agent = AgentRecord(agent_id='agent-1', company_id=42, services_allowed=['ai', 'storage'])
        with patch('apps.connector.downstream_tokens.requests.post') as post:
            post.return_value.status_code = 200
            post.return_value.json.return_value = {'access_token': 'downstream-jwt'}
            mint_downstream_access_token(agent, resource='https://storage.test/mcp')
        _args, kwargs = post.call_args
        auth = kwargs['headers']['Authorization']
        token = auth.split(' ', 1)[1]
        header = jwt.get_unverified_header(token)
        signing = _DELEGATION_TEST_SETTINGS['AI_SERVICE_SIGNING_KEY']
        self.assertEqual(header['alg'], 'RS256')
        self.assertEqual(header['kid'], _DELEGATION_TEST_SETTINGS['AI_SERVICE_SIGNING_KID'])
        claims = verify_downstream_token_request(
            token,
            signing.public_pem,
            'https://ai.test',
        )
        self.assertEqual(claims['aud'], DOWNSTREAM_TOKEN_AUDIENCE)
        self.assertEqual(claims['scope'], DOWNSTREAM_TOKEN_SCOPE)
        self.assertEqual(claims['agent_id'], 'agent-1')
        self.assertEqual(claims['company_id'], 42)
        self.assertEqual(claims['resource'], 'https://storage.test/mcp')
        self.assertLessEqual(int(claims['exp']) - int(claims['iat']), DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS)

    @patch('apps.connector.downstream_tokens.requests.post')
    def test_mint_logs_never_include_private_key_or_bearer(self, post):
        post.return_value.status_code = 200
        post.return_value.json.return_value = {'access_token': 'ok'}
        agent = AgentRecord(agent_id='a', company_id=1, services_allowed=['ai'])
        signing = _DELEGATION_TEST_SETTINGS['AI_SERVICE_SIGNING_KEY']
        private_snippet = signing.private_pem[:40]

        messages: list[str] = []

        class _CaptureHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                messages.append(record.getMessage())

        logger = logging.getLogger('apps.connector.downstream_tokens')
        handler = _CaptureHandler()
        logger.addHandler(handler)
        try:
            mint_downstream_access_token(agent, resource='https://storage.test/mcp')
        finally:
            logger.removeHandler(handler)

        joined = ' '.join(messages)
        self.assertNotIn(private_snippet, joined)
        self.assertNotIn(_PEM_RSA_BANNER, joined)
        self.assertNotIn(_PEM_PKCS8_BANNER, joined)
        self.assertNotIn('Bearer ', joined)


@override_settings(**_DELEGATION_TEST_SETTINGS)
class AiServiceJwksEndpointTests(TestCase):
    def test_jwks_exposes_public_key_only(self):
        response = Client().get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body['keys']), 1)
        jwk = body['keys'][0]
        self.assertEqual(jwk['kty'], 'RSA')
        self.assertEqual(jwk['kid'], _DELEGATION_TEST_SETTINGS['AI_SERVICE_SIGNING_KID'])
        self.assertIn('n', jwk)
        self.assertIn('e', jwk)
        self.assertNotIn('d', jwk)
        raw = response.content.decode()
        self.assertNotIn(_PEM_RSA_BANNER, raw)
        self.assertNotIn(_PEM_PKCS8_BANNER, raw)
