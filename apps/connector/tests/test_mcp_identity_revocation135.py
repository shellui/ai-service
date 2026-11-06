"""Revocation poll verification (commons #14 / identity #135)."""

from __future__ import annotations

import time
import uuid

import jwt
from django.test import SimpleTestCase, override_settings

from apps.authapi.ai_service_jwks import build_jwks_document, compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from shellui_django.mcp.internal import REVOCATION_AUDIENCE, REVOCATION_LIST_SCOPE, InternalAssertionError

from apps.connector.mcp_identity import (
    parse_trusted_revocation_poll_response_identity135,
    verify_mcp_revocation_list_response_identity135,
)

_ID_PRIVATE, _ID_PUBLIC = generate_rsa_key_pair(key_size=2048)
_ID_SIGNING = load_ai_service_signing_key(private_pem=_ID_PRIVATE, kid=compute_rsa_kid(_ID_PUBLIC))
_JWKS = build_jwks_document(_ID_SIGNING)
_ISSUER = 'https://identity.revoke.test'


def _list_token(*, policy_version: int | None, max_active_grant_version: int | None = None) -> str:
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
        'jti': uuid.uuid4().hex,
    }
    if policy_version is not None:
        claims['revocation_policy_version'] = int(policy_version)
    if max_active_grant_version is not None:
        claims['max_active_grant_version'] = int(max_active_grant_version)
    token = jwt.encode(claims, _ID_SIGNING.private_pem, algorithm='RS256', headers={'kid': _ID_SIGNING.kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


@override_settings(IDENTITY_ISSUER=_ISSUER)
class RevocationPolicyVersionTests(SimpleTestCase):
    def test_trusted_response_includes_policy_version(self):
        body = {
            'revocation_assertion': _list_token(policy_version=1),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
            'revocation_policy_version': 1,
        }
        ids, ttl, agents, ver = parse_trusted_revocation_poll_response_identity135(
            body,
            expected_issuer=_ISSUER,
            jwks=_JWKS,
        )
        self.assertIn('agent-x', ids)
        self.assertEqual(ttl, 30)
        self.assertEqual(ver, 1)
        self.assertEqual(agents, [])

    def test_body_policy_version_mismatch_fails_closed(self):
        body = {
            'revocation_assertion': _list_token(policy_version=1),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
            'revocation_policy_version': 2,
        }
        with self.assertRaises(InternalAssertionError):
            parse_trusted_revocation_poll_response_identity135(body, expected_issuer=_ISSUER, jwks=_JWKS)

    def test_jwt_policy_version_without_body_fails_closed(self):
        body = {
            'revocation_assertion': _list_token(policy_version=1),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
        }
        with self.assertRaises(InternalAssertionError):
            parse_trusted_revocation_poll_response_identity135(body, expected_issuer=_ISSUER, jwks=_JWKS)

    def test_max_active_grant_version_must_match_body(self):
        """Signed ``max_active_grant_version`` is fail-closed unless the JSON body echoes it."""
        token = _list_token(policy_version=4, max_active_grant_version=0)
        omitted = {
            'revocation_assertion': token,
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
            'revocation_policy_version': 4,
        }
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response_identity135(omitted, expected_issuer=_ISSUER, jwks=_JWKS)
        mismatched = {**omitted, 'max_active_grant_version': 1}
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response_identity135(mismatched, expected_issuer=_ISSUER, jwks=_JWKS)
        echoed = {**omitted, 'max_active_grant_version': 0}
        trusted = verify_mcp_revocation_list_response_identity135(echoed, expected_issuer=_ISSUER, jwks=_JWKS)
        self.assertEqual(trusted.get('max_active_grant_version'), 0)

    def test_body_policy_version_without_jwt_fails_closed(self):
        body = {
            'revocation_assertion': _list_token(policy_version=None),
            'revoked_agent_ids': ['agent-x'],
            'cache_seconds': 30,
            'agents': [],
            'revocation_policy_version': 1,
        }
        with self.assertRaises(InternalAssertionError):
            parse_trusted_revocation_poll_response_identity135(body, expected_issuer=_ISSUER, jwks=_JWKS)
