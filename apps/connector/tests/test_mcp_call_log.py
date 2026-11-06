from __future__ import annotations

from django.test import SimpleTestCase

from apps.connector.mcp_call_log import (
    apply_duration_ms,
    begin_mcp_tool_call_timer,
    reset_mcp_tool_call_timer,
)


class McpCallLogDurationTests(SimpleTestCase):
    def test_apply_duration_ms_uses_timer(self):
        token = begin_mcp_tool_call_timer()
        try:
            entry: dict = {}
            apply_duration_ms(entry)
            self.assertIn('duration_ms', entry)
            self.assertGreaterEqual(entry['duration_ms'], 0)
        finally:
            reset_mcp_tool_call_timer(token)

    def test_apply_duration_ms_keeps_explicit_value(self):
        entry = {'duration_ms': 99}
        apply_duration_ms(entry)
        self.assertEqual(entry['duration_ms'], 99)
