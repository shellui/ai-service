from django.test import SimpleTestCase

from apps.connector.mcp_tool_naming import (
    canonical_downstream_tool_name,
    gateway_export_name,
    legacy_slug_tool_name,
    resolve_mcp_tool_name,
    select_newest_api_version_operations,
    validate_tool_name,
    clamp_tool_name,
)


class McpToolNamingTests(SimpleTestCase):
    def test_legacy_slug(self):
        self.assertEqual(
            legacy_slug_tool_name('get', '/api/v1/templates/', 'api_v1_templates_list'),
            'api_v1_templates_list',
        )

    def test_clean_names(self):
        op = {'operationId': 'api_v1_actions_rules_create', 'tags': ['mcp-tools']}
        self.assertEqual(resolve_mcp_tool_name(op, 'post', '/api/v1/actions/rules/'), 'create_rules')
        op = {'operationId': 'api_v1_users_list', 'tags': ['mcp-tools']}
        self.assertEqual(resolve_mcp_tool_name(op, 'get', '/api/v1/users/'), 'list_users')
        op = {'operationId': 'api_v1_mcp_services_list', 'tags': ['mcp-tools']}
        self.assertEqual(resolve_mcp_tool_name(op, 'get', '/api/v1/mcp/services/'), 'list_services')

    def test_gateway_prefix(self):
        self.assertEqual(gateway_export_name('email', 'send_message'), 'email_send_message')

    def test_canonical_legacy_downstream_name(self):
        self.assertEqual(
            canonical_downstream_tool_name('api_v1_actions_deliveries_list'),
            'list_deliveries',
        )
        self.assertEqual(
            canonical_downstream_tool_name('identity_api_v1_users_list', service_id='identity'),
            'list_users',
        )

    def test_newest_api_version(self):
        schema = {
            'paths': {
                '/api/v1/widgets/': {'get': {'tags': ['mcp-tools'], 'operationId': 'api_v1_widgets_list'}},
                '/api/v2/widgets/': {'get': {'tags': ['mcp-tools'], 'operationId': 'api_v2_widgets_list'}},
            },
        }
        picked = select_newest_api_version_operations(schema)
        self.assertEqual(len(picked), 1)
        self.assertEqual(picked[0][0], '/api/v2/widgets/')

    def test_clamp(self):
        self.assertEqual(validate_tool_name(clamp_tool_name('a' * 80)), [])
