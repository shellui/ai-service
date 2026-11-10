"""Partial global triple rejects internal MCP approval paths (identity #135).

Personal regional tokens from identity ``build_agent_access_token`` always include
``grant_version`` and omit ``global_company_id`` / ``company_binding_version``.
That lone version is not a partial triple on the approval assertion path.
"""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import MagicMock, patch

import jwt
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from apps.connector import mcp_approvals
from apps.connector.mcp_setup_context import approval_assertion_context_from_agent_claims
from shellui_django.mcp.internal import APPROVAL_AUDIENCE

_GV = 1
_CBV = 1
_GLOBAL_CO = '11111111-1111-4111-8111-111111111111'
_AGENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))
_HS_SECRET = 'test-hs256-secret-for-mcp-gateway-tests-only'  # gitleaks:allow
AI_MCP_1 = 'https://ai.test/c/1/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'


def _personal_identity_claims(*, now: int | None = None, grant_version: int = _GV) -> dict:
    """Claim set identity issues for a regional device-login agent (not global delegated)."""
    issued = int(time.time()) if now is None else now
    return {
        'token_type': 'access',
        'agent_id': _AGENT,
        'sub': f'agent:{_AGENT}',
        'company_id': 1,
        'company_name': 'Acme',
        'mcp_access': 'ask',
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'scope': 'ai email',
        'jti': 'device-jti-personal',
        'iat': issued,
        'exp': issued + 900,
        'aud': AI_MCP_1,
        'iss': 'https://identity.test',
        'grant_version': grant_version,
    }


def _personal_approval_payload(*, grant_version: int = _GV) -> dict:
    return {
        'agent_id': _AGENT,
        'company_id': 1,
        'service': 'email',
        'action': 'email_create_template_versions',
        'arguments_hash': 'ab' * 32,
        '_agent_claims': _personal_identity_claims(grant_version=grant_version),
    }


def _approval_http(url, **kwargs):
    path = str(url).rstrip('/')
    resp = MagicMock()
    if path.endswith('/mcp-approval-requests'):
        resp.status_code = 201
        resp.json.return_value = {'id': 'appr-personal', 'status': 'pending'}
        return resp
    if path.endswith('/mcp-approval-state'):
        resp.status_code = 200
        resp.json.return_value = {'id': 'appr-personal', 'status': 'pending'}
        return resp
    if path.endswith('/mcp-approval-consume'):
        resp.status_code = 200
        resp.json.return_value = {'consumed': True}
        return resp
    raise AssertionError(f'unexpected approval URL: {url}')


@override_settings(
    AI_SERVICE_ISSUER='https://ai.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
)
class GlobalBindingConflictTests(TestCase):
    def test_personal_grant_version_only_is_not_a_binding_conflict(self):
        ctx = approval_assertion_context_from_agent_claims(_personal_identity_claims())
        self.assertFalse(ctx.blocked_assertion)
        self.assertFalse(ctx.is_global_delegated)
        self.assertFalse(ctx.setup_flow)
        self.assertEqual(ctx.grant_version, _GV)
        self.assertIsNone(ctx.global_company_id)
        self.assertIsNone(ctx.company_binding_version)

    def test_personal_grant_version_zero_is_not_a_binding_conflict(self):
        """Identity writes ``grant_version`` 0 when the agent has never been bumped."""
        ctx = approval_assertion_context_from_agent_claims(_personal_identity_claims(grant_version=0))
        self.assertFalse(ctx.blocked_assertion)
        self.assertEqual(ctx.grant_version, 0)
        self.assertIsNone(ctx.company_binding_version)
        self.assertIsNone(ctx.global_company_id)

    def test_setup_flow_without_full_triple_stays_blocked(self):
        now = int(time.time())
        claims = _personal_identity_claims(now=now)
        claims.update(
            {
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'setup_expires_at': (timezone.now() + timedelta(seconds=650)).isoformat(),
            }
        )
        ctx = approval_assertion_context_from_agent_claims(claims)
        self.assertTrue(ctx.blocked_assertion)
        self.assertFalse(ctx.setup_flow)

    def _assert_personal_assertion(self, post, *, grant_version: int = _GV) -> None:
        post.assert_called_once()
        header = post.call_args.kwargs['headers']['Authorization']
        self.assertTrue(header.startswith('Bearer '))
        claims = jwt.decode(
            header.split(' ', 1)[1],
            _SIGNING.public_pem,
            algorithms=['RS256'],
            audience=APPROVAL_AUDIENCE,
            issuer='https://ai.test',
            options={'verify_aud': True},
        )
        self.assertEqual(claims.get('grant_version'), grant_version)
        self.assertNotIn('global_company_id', claims)
        self.assertNotIn('company_binding_version', claims)
        self.assertEqual(claims.get('service'), 'email')
        self.assertEqual(claims.get('action'), 'email_create_template_versions')

    @patch('apps.connector.mcp_approvals.requests.post', side_effect=_approval_http)
    def test_personal_create_sends_assertion_with_grant_version(self, post):
        created = mcp_approvals.create_approval_request(_personal_approval_payload())
        self.assertEqual(created['id'], 'appr-personal')
        self.assertEqual(created['status'], 'pending')
        self.assertEqual(
            created['approval_url'],
            'https://identity.test/oauth/mcp/approval/appr-personal',
        )
        self.assertTrue(str(post.call_args.args[0]).endswith('/mcp-approval-requests'))
        self._assert_personal_assertion(post)

    @patch('apps.connector.mcp_approvals.requests.post', side_effect=_approval_http)
    def test_personal_state_lookup_sends_assertion_with_grant_version(self, post):
        status, approval_id = mcp_approvals.fetch_approval_state(_personal_approval_payload())
        self.assertEqual(status, 'pending')
        self.assertEqual(approval_id, 'appr-personal')
        self.assertTrue(str(post.call_args.args[0]).endswith('/mcp-approval-state'))
        self._assert_personal_assertion(post)

    @patch('apps.connector.mcp_approvals.requests.post', side_effect=_approval_http)
    def test_personal_consume_sends_assertion_with_grant_version(self, post):
        result = mcp_approvals.consume_approval_detail('appr-personal', _personal_approval_payload())
        self.assertTrue(result.consumed)
        self.assertTrue(str(post.call_args.args[0]).endswith('/mcp-approval-consume'))
        body = post.call_args.kwargs.get('json') or {}
        self.assertEqual(body.get('approval_id'), 'appr-personal')
        self._assert_personal_assertion(post)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_create_skipped_when_partial_triple(self, post):
        """``company_binding_version`` without ``global_company_id`` is still a partial triple."""
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'x',
            'arguments_hash': 'h' * 64,
            '_agent_claims': {
                'iat': int(time.time()),
                'exp': int(time.time()) + 3600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
            },
        }
        self.assertIsNone(mcp_approvals.create_approval_request(payload))
        post.assert_not_called()

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_partial_global_triples_still_block_create_state_and_consume(self, post):
        now = int(time.time())
        base = {'iat': now, 'exp': now + 3600, 'agent_id': _AGENT, 'company_id': 1}
        partials = (
            {**base, 'global_company_id': _GLOBAL_CO},
            {**base, 'company_binding_version': _CBV},
            {**base, 'grant_version': _GV, 'company_binding_version': _CBV},
            {**base, 'grant_version': _GV, 'global_company_id': 'not-a-uuid'},
            {**base, 'global_company_id': 'not-a-uuid'},
            {**base, 'grant_version': _GV, 'global_company_id': _GLOBAL_CO},
            {**base, 'mcp_authority': 'delegated', 'grant_version': _GV},
            {**base, 'mcp_authority': 'global_delegated'},
            {**base, 'mcp_authority': 'global_delegated', 'grant_version': _GV},
            {
                **base,
                'mcp_authority': 'delegated',
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
            },
        )
        for claims in partials:
            ctx = approval_assertion_context_from_agent_claims(claims)
            self.assertTrue(ctx.blocked_assertion, claims)
            payload = {
                'agent_id': _AGENT,
                'company_id': 1,
                'service': 'email',
                'action': 'email_create_template_versions',
                'arguments_hash': 'cd' * 32,
                '_agent_claims': claims,
            }
            self.assertIsNone(mcp_approvals.create_approval_request(payload), claims)
            self.assertEqual(mcp_approvals.fetch_approval_state(payload), (None, None), claims)
            self.assertFalse(
                mcp_approvals.consume_approval_detail('appr-personal', payload).consumed,
                claims,
            )
        post.assert_not_called()
