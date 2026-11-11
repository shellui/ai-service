"""Unit tests for MCP call audit outcome mapping."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.connector.mcp_call_audit import (
    OUTCOMES,
    build_call_audit_log,
    legacy_result_token,
    outcome_from_audit,
    operation_title_for_audit,
    resource_label_safe,
)


class McpCallAuditOutcomeTests(SimpleTestCase):
    def test_maps_client_session_to_session_used(self):
        self.assertEqual(
            outcome_from_audit(log_result='client_session_allowed', status=200, is_error=False),
            'session_used',
        )

    def test_maps_identity_approved_human_status_to_allowed(self):
        self.assertEqual(
            outcome_from_audit(log_result='identity_approved', status=200, is_error=False),
            'allowed',
        )

    def test_maps_error_status_to_failed(self):
        self.assertEqual(outcome_from_audit(log_result=None, status=502, is_error=None), 'failed')

    def test_http200_with_is_error_maps_to_failed(self):
        """MCP JSON-RPC often uses HTTP 200 with result.isError true."""
        self.assertEqual(outcome_from_audit(log_result=None, status=200, is_error=True), 'failed')

    def test_http200_unknown_log_result_fail_closed(self):
        self.assertEqual(outcome_from_audit(log_result='weird', status=200, is_error=None), 'failed')

    def test_pending_approval_synonym(self):
        self.assertEqual(
            outcome_from_audit(log_result='pending_approval', status=202, is_error=None),
            'pending_approval',
        )

    def test_legacy_pending_log_result_maps_to_pending_approval_outcome(self):
        self.assertEqual(
            outcome_from_audit(log_result='pending', status=202, is_error=None),
            'pending_approval',
        )

    def test_legacy_result_token_pending_is_pending_approval(self):
        self.assertEqual(legacy_result_token(outcome='pending'), 'pending_approval')
        self.assertEqual(legacy_result_token(outcome='pending_approval'), 'pending_approval')

    def test_outcomes_set(self):
        self.assertEqual(OUTCOMES, {'allowed', 'failed', 'denied', 'pending_approval', 'session_used'})

    def test_hostile_error_code_dropped(self):
        row = build_call_audit_log(
            agent_claims={'agent_id': 'a', 'company_id': 1},
            service_id='storage',
            export_name='x',
            tool=None,
            method='POST',
            path='/p',
            log_result='error',
            status=500,
            is_error=True,
            error_code='provider_error DROP TABLE;',
        )
        self.assertEqual(row.get('error_code'), 'internal_error')

    def test_mcp_tool_error_allowlisted(self):
        row = build_call_audit_log(
            agent_claims={'agent_id': 'a', 'company_id': 1},
            service_id='storage',
            export_name='x',
            tool=None,
            method='GET',
            path='',
            log_result='error',
            status=200,
            is_error=True,
            error_code='mcp_tool_error',
        )
        self.assertEqual(row.get('error_code'), 'mcp_tool_error')

    def test_operation_title_neutral_when_broker_hint(self):
        tool = {'_meta': {'operation_summary': 'Ask broker queue', 'path': '/a'}, 'title': 'Name'}
        self.assertTrue(operation_title_for_audit(tool, export_name='svc_tool', method='POST').startswith('Operation '))

    def test_resource_label_strips_query(self):
        tool = {'_meta': {'path': '/items/{id}/'}}
        label = resource_label_safe(method='GET', path='https://x.test/items/1?secret=1', tool=tool)
        self.assertNotIn('?', label)

    def test_audit_path_strips_query_and_fragment(self):
        tool = {'_meta': {'path': '/api/resource/{id}'}}
        row = build_call_audit_log(
            agent_claims={'agent_id': 'a', 'company_id': 1},
            service_id='storage',
            export_name='t',
            tool=tool,
            method='GET',
            path='/api/resource/1?q=abc#frag',
            log_result='success',
            status=200,
            is_error=False,
        )
        self.assertEqual(row['path'], '/api/resource/{id}')
        self.assertNotIn('?', row['resource_label'])
        self.assertNotIn('#', row['resource_label'])

    def test_access_kind_empty_method_is_write_without_tool(self):
        row = build_call_audit_log(
            agent_claims={'agent_id': 'a', 'company_id': 1},
            service_id='storage',
            export_name='x',
            tool=None,
            method='',
            path='/p',
            log_result='success',
            status=200,
            is_error=False,
        )
        self.assertEqual(row['access_kind'], 'write')

    def test_operation_title_meta_summary_only_not_tool_title(self):
        tool = {'title': 'List users from response', '_meta': {'operation_summary': 'List all users'}}
        self.assertEqual(
            operation_title_for_audit(tool, export_name='svc_list_users', method='GET'),
            'List all users',
        )

    def test_operation_title_without_meta_summary_is_neutral(self):
        tool = {'title': 'Untrusted downstream title'}
        self.assertTrue(
            operation_title_for_audit(tool, export_name='svc_list_users', method='GET').startswith('Operation '),
        )

    def test_resource_label_without_path_meta_uses_export_id_not_raw_path(self):
        label = resource_label_safe(
            method='GET',
            path='/users/secret@x.test/items/1?q=hide',
            tool={'name': 'legacy'},
            export_name='storage_list_items',
        )
        self.assertIn('gateway:storage_list_items', label)
        self.assertNotIn('@', label)
        self.assertNotIn('?', label)

    def test_neutral_title_not_doubled_when_export_starts_with_operation(self):
        self.assertEqual(
            operation_title_for_audit(None, export_name='Operation list_users', method='POST'),
            'Operation list_users',
        )
