"""Unit tests for MCP call audit outcome mapping."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.connector.mcp_call_audit import (
    OUTCOMES,
    outcome_from_audit,
)


class McpCallAuditOutcomeTests(SimpleTestCase):
    def test_maps_client_session_to_session_used(self):
        self.assertEqual(
            outcome_from_audit(log_result='client_session_allowed', status=200, is_error=False),
            'session_used',
        )

    def test_maps_error_status_to_failed(self):
        self.assertEqual(outcome_from_audit(log_result=None, status=502, is_error=None), 'failed')

    def test_outcomes_set(self):
        self.assertEqual(OUTCOMES, {'allowed', 'failed', 'denied', 'pending', 'session_used'})
