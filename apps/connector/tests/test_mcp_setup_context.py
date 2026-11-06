"""Tests for server-derived MCP approval assertion context."""

from __future__ import annotations

import time

from django.test import TestCase, override_settings

from apps.connector.mcp_setup_context import approval_assertion_context_from_agent_claims


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
        ctx = approval_assertion_context_from_agent_claims(
            {
                'setup_flow': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now,
                'exp': now + 900,
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
                'setup_flow': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now - 800,
                'exp': now + 120,
            },
        )
        self.assertEqual(ctx.lifetime_seconds, 60)
        self.assertFalse(ctx.setup_flow)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_setup_rejected_when_wall_clock_remaining_too_short(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'setup_flow': True,
                'mcp_session_ttl_seconds': 600,
                'iat': now - 3600,
                'exp': now + 30,
            },
        )
        self.assertEqual(ctx.lifetime_seconds, 60)
        self.assertFalse(ctx.setup_flow)

    @override_settings(
        MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS=600,
        MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS=900,
        MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS=900,
    )
    def test_out_of_band_ttl_rejected(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {
                'setup_flow': True,
                'mcp_session_ttl_seconds': 120,
                'iat': now,
                'exp': now + 900,
            },
        )
        self.assertEqual(ctx.lifetime_seconds, 60)
        self.assertFalse(ctx.setup_flow)
