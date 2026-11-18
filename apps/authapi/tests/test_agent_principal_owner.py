"""Agent bearer principal reconstruction (least privilege)."""

from __future__ import annotations

import time
from unittest.mock import patch

import jwt
from django.test import TestCase, override_settings

from apps.authapi.agent_tokens import authenticate_agent_bearer

_AI = 'https://ai.test/c/7/mcp'


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-agent-principal',  # gitleaks:allow
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_JWKS_URL='',
)
@patch('apps.authapi.agent_tokens.get_jwks_client')
class AgentPrincipalOwnerTests(TestCase):
    def _claims(self, **extra):
        now = int(time.time())
        base = {
            'token_type': 'access',
            'sub': 'agent:x',
            'agent_id': 'x',
            'company_id': 7,
            'scope': 'ai',
            'mcp_access': 'read_only',
            'aud': _AI,
            'iss': 'https://identity.test',
            'iat': now,
            'exp': now + 3600,
        }
        base.update(extra)
        return base

    def test_owner_false_by_default(self, jwks):
        jwks.return_value.get_signing_key.return_value = None
        token = jwt.encode(
            self._claims(),
            'test-hs256-secret-agent-principal',  # gitleaks:allow
            algorithm='HS256',
        )
        principal, _claims = authenticate_agent_bearer(token, expected_resource=_AI)
        self.assertIsNotNone(principal)
        assert principal is not None
        self.assertFalse(principal.is_company_owner)

    def test_owner_from_claims(self, jwks):
        jwks.return_value.get_signing_key.return_value = None
        token = jwt.encode(
            self._claims(is_company_owner=True),
            'test-hs256-secret-agent-principal',  # gitleaks:allow
            algorithm='HS256',
        )
        principal, _claims = authenticate_agent_bearer(token, expected_resource=_AI)
        self.assertIsNotNone(principal)
        assert principal is not None
        self.assertTrue(principal.is_company_owner)
