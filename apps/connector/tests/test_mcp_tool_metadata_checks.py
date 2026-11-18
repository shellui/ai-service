from django.test import SimpleTestCase

from apps.connector.mcp_tool_metadata_checks import validate_gateway_tool_name, validate_tool_metadata


class McpToolMetadataChecksTests(SimpleTestCase):
    def test_gateway_name_pattern(self):
        self.assertEqual(validate_gateway_tool_name('email_send_message'), [])
        self.assertIn('pattern', validate_gateway_tool_name('email_send'))
        self.assertIn('forbidden_substring', validate_gateway_tool_name('email_api_v1_send'))
        self.assertIn('numeric_collision_suffix', validate_gateway_tool_name('identity_list_events_2'))

    def test_tool_metadata(self):
        tool = {
            'name': 'storage_list_buckets',
            'title': 'Storage: List buckets',
            'description': 'Lists storage buckets for the company.',
            'annotations': {
                'readOnlyHint': True,
                'destructiveHint': False,
                'idempotentHint': True,
                'openWorldHint': False,
            },
        }
        self.assertEqual(validate_tool_metadata(tool), [])

    def test_rejects_api_version_in_title(self):
        tool = {
            'name': 'identity_list_users',
            'title': 'API V1 List users',
            'description': 'Lists users for the company workspace.',
            'annotations': {
                'readOnlyHint': True,
                'destructiveHint': False,
                'idempotentHint': True,
                'openWorldHint': False,
            },
        }
        errors = validate_tool_metadata(tool)
        self.assertTrue(any('API version' in line for line in errors))
        self.assertTrue(any('service name' in line for line in errors))
