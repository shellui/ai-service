"""Unit tests for MCP call audit outcome mapping."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.connector.mcp_call_audit import (
    OUTCOMES,
    build_call_audit_log,
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

    def test_maps_error_status_to_failed(self):
        self.assertEqual(outcome_from_audit(log_result=None, status=502, is_error=None), 'failed')

    def test_outcomes_set(self):
        self.assertEqual(OUTCOMES, {'allowed', 'failed', 'denied', 'pending', 'session_used'})

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

    def test_operation_title_neutral_when_broker_hint(self):
        tool = {'_meta': {'operation_summary': 'Ask broker queue', 'path': '/a'}, 'title': 'Name'}
        self.assertTrue(operation_title_for_audit(tool, export_name='svc_tool', method='POST').startswith('Operation '))

    def test_resource_label_strips_query(self):
        tool = {'_meta': {'path': '/items/{id}/'}}
        label = resource_label_safe(method='GET', path='https://x.test/items/1?secret=1', tool=tool)
        self.assertNotIn('?', label)

    def test_audit_path_strips_query_and_fragment(self):
        row = build_call_audit_log(
            agent_claims={'agent_id': 'a', 'company_id': 1},
            service_id='storage',
            export_name='t',
            tool=None,
            method='GET',
            path='/api/resource?q=abc#frag',
            log_result='success',
            status=200,
            is_error=False,
        )
        self.assertEqual(row['path'], '/api/resource')
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

    def test_operation_title_uses_registry_title_without_path_meta(self):
        tool = {'title': 'List users', '_meta': {'operation_summary': 'List all users'}}
        self.assertEqual(
            operation_title_for_audit(tool, export_name='svc_list_users', method='GET'),
            'List all users',
        )

    def test_neutral_title_not_doubled_when_export_starts_with_operation(self):
        self.assertEqual(
            operation_title_for_audit(None, export_name='Operation list_users', method='POST'),
            'Operation list_users',
        )
