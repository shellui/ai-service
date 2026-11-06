"""Tests for server-derived MCP approval assertion context."""

from __future__ import annotations

import time
import uuid
from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.connector.mcp_setup_context import approval_assertion_context_from_agent_claims

_GV = 1
_CBV = 1
_GLOBAL_CO = '11111111-1111-4111-8111-111111111111'


class McpSetupContextTests(TestCase):
    def test_default_no_setup_claims(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {'setup_flow': False, 'iat': now, 'exp': now + 3600},
        )
        self.assertEqual(ctx.lifetime_seconds, 60)
        self.assertFalse(ctx.setup_flow)
        self.assertIsNone(ctx.mcp_session_ttl_seconds)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_valid_setup_from_claims(self):
        now = int(time.time())
        setup_exp = timezone.now() + timedelta(seconds=650)
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now,
                'exp': now + 900,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': setup_exp.isoformat(),
            },
        )
        self.assertTrue(ctx.setup_flow)
        self.assertEqual(ctx.mcp_session_ttl_seconds, 600)
        self.assertEqual(ctx.lifetime_seconds, 600)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_setup_ttl_cannot_exceed_jwt_window(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': (timezone.now() + timedelta(seconds=650)).isoformat(),
                'iat': now - 800,
                'exp': now + 120,
            },
        )
        self.assertEqual(ctx.lifetime_seconds, 60)
        self.assertFalse(ctx.setup_flow)
        self.assertTrue(ctx.blocked_assertion)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_setup_rejected_when_wall_clock_remaining_too_short(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': (timezone.now() + timedelta(seconds=650)).isoformat(),
                'iat': now - 3600,
                'exp': now + 30,
            },
        )
        self.assertEqual(ctx.lifetime_seconds, 60)
        self.assertFalse(ctx.setup_flow)
        self.assertTrue(ctx.blocked_assertion)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_out_of_band_ttl_rejected(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 120,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': (timezone.now() + timedelta(seconds=650)).isoformat(),
                'iat': now,
                'exp': now + 900,
            },
        )
        self.assertEqual(ctx.lifetime_seconds, 60)
        self.assertFalse(ctx.setup_flow)
        self.assertTrue(ctx.blocked_assertion)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_uuid_company_id_rejects_setup(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': str(uuid.uuid4()),
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': (timezone.now() + timedelta(seconds=650)).isoformat(),
                'iat': now,
                'exp': now + 900,
            },
        )
        self.assertFalse(ctx.setup_flow)
        self.assertTrue(ctx.blocked_assertion)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_setup_expires_at_from_claims(self):
        now = int(time.time())
        exp_wall = now + 900
        setup_exp = timezone.now() + timedelta(seconds=650)
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now,
                'exp': exp_wall,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': setup_exp.isoformat(),
            },
        )
        self.assertTrue(ctx.setup_flow)
        self.assertIsNotNone(ctx.setup_expires_at)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_setup_requires_setup_expires_at_on_token(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now,
                'exp': now + 900,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
            },
        )
        self.assertFalse(ctx.setup_flow)
        self.assertTrue(ctx.blocked_assertion)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_setup_requires_new_company_grant(self):
        now = int(time.time())
        setup_exp = timezone.now() + timedelta(seconds=650)
        ctx = approval_assertion_context_from_agent_claims(
            {
                'company_id': 10,
                'setup_flow': True,
                'mcp_new_company_grant': False,
                'mcp_session_ttl_seconds': 600,
                'iat': now,
                'exp': now + 900,
                'grant_version': _GV,
                'company_binding_version': _CBV,
                'global_company_id': _GLOBAL_CO,
                'setup_expires_at': setup_exp.isoformat(),
            },
        )
        self.assertFalse(ctx.setup_flow)
        self.assertTrue(ctx.blocked_assertion)

    def test_integer_zero_versions_preserved_in_fallback(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'setup_flow': False,
                'iat': now,
                'exp': now + 3600,
                'grant_version': 0,
                'company_binding_version': 0,
                'global_company_id': _GLOBAL_CO,
            },
        )
        self.assertEqual(ctx.grant_version, 0)
        self.assertEqual(ctx.company_binding_version, 0)
