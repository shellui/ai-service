"""Call audit: service claim vs tool service id."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.connector.mcp_call_audit import build_call_audit_log


class McpCallAuditServiceMatchTests(SimpleTestCase):
    def test_mismatched_service_yields_failed_outcome(self):
        row = build_call_audit_log(
            agent_claims={
                'agent_id': 'a',
                'company_id': 1,
                'service': 'storage',
            },
            service_id='saas',
            export_name='x',
            tool=None,
            method='POST',
            path='/p',
            log_result='success',
            status=200,
            is_error=False,
        )
        self.assertEqual(row['outcome'], 'failed')

    def test_matching_service_uses_audit_outcome(self):
        row = build_call_audit_log(
            agent_claims={
                'agent_id': 'a',
                'company_id': 1,
                'service': 'storage',
            },
            service_id='storage',
            export_name='x',
            tool=None,
            method='POST',
            path='/p',
            log_result='success',
            status=200,
            is_error=False,
        )
        self.assertEqual(row['outcome'], 'allowed')
