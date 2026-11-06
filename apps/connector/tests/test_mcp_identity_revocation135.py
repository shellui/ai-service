"""Revocation poll verification for identity #135 (signed policy version)."""

from __future__ import annotations

import time

import jwt
from django.test import SimpleTestCase, override_settings

from apps.authapi.ai_service_jwks import build_jwks_document, compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from shellui_django.mcp.internal import REVOCATION_AUDIENCE, REVOCATION_LIST_SCOPE, InternalAssertionError

from apps.connector.mcp_identity import parse_trusted_revocation_poll_response_identity135

_ID_PRIVATE, _ID_PUBLIC = generate_rsa_key_pair(key_size=2048)
_ID_SIGNING = load_ai_service_signing_key(private_pem=_ID_PRIVATE, kid=compute_rsa_kid(_ID_PUBLIC))
_JWKS = build_jwks_document(_ID_SIGNING)
_ISSUER = 'https://identity.revoke.test'


def _list_token(*, jwt_version: str | None) -> str:
    now = int(time.time())
    claims: dict = {
        'iss': _ISSUER,
        'aud': REVOCATION_AUDIENCE,
        'sub': 'identity',
        'scope': REVOCATION_LIST_SCOPE,
        'revoked_agent_ids': ['agent-x'],
        'agents': [],
        'cache_seconds': 30,
        'iat': now,
        'exp': now + 120,
    }
    if jwt_version is not None:
        claims['revocation_policy_version'] = jwt_version
    token = jwt.encode(claims, _ID_SIGNING.private_pem, algorithm='RS256', headers={'kid': _ID_SIGNING.kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(IDENTITY_ISSUER=_ISSUER)
class RevocationPolicyVersionTests(SimpleTestCase):
    def test_trusted_response_includes_policy_version(self):
        body = {
            'revocation_assertion': _list_token(jwt_version='p1'),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
            'revocation_policy_version': 'p1',
        }
        ids, ttl, agents, ver = parse_trusted_revocation_poll_response_identity135(
            body,
            expected_issuer=_ISSUER,
            jwks=_JWKS,
        )
        self.assertIn('agent-x', ids)
        self.assertEqual(ttl, 30)
        self.assertEqual(ver, 'p1')
        self.assertEqual(agents, [])

    def test_body_policy_version_mismatch_fails_closed(self):
        body = {
            'revocation_assertion': _list_token(jwt_version='p1'),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
            'revocation_policy_version': 'p2',
        }
        with self.assertRaises(InternalAssertionError):
            parse_trusted_revocation_poll_response_identity135(body, expected_issuer=_ISSUER, jwks=_JWKS)

    def test_jwt_policy_version_without_body_fails_closed(self):
        body = {
            'revocation_assertion': _list_token(jwt_version='p1'),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
        }
        with self.assertRaises(InternalAssertionError):
            parse_trusted_revocation_poll_response_identity135(body, expected_issuer=_ISSUER, jwks=_JWKS)

    def test_body_policy_version_without_jwt_fails_closed(self):
        body = {
            'revocation_assertion': _list_token(jwt_version=None),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
            'revocation_policy_version': 'p1',
        }
        with self.assertRaises(InternalAssertionError):
            parse_trusted_revocation_poll_response_identity135(body, expected_issuer=_ISSUER, jwks=_JWKS)
