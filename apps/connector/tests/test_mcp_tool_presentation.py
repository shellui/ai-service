from django.test import SimpleTestCase

from apps.connector.mcp_tool_presentation import (
    apply_company_scope_to_tool,
    apply_gateway_tool_presentation,
    apply_tool_presentation,
    ensure_service_first_title,
    sanitize_shellui_copy,
    shellui_gateway_instructions,
    strip_presentation_noise,
    tool_annotations,
)


class McpToolPresentationTests(SimpleTestCase):
    def test_sanitize_shellui_copy(self):
        self.assertEqual(sanitize_shellui_copy('shellui — test'), 'Shellui, test')

    def test_strip_presentation_noise(self):
        self.assertEqual(strip_presentation_noise('API V1 List users'), 'List users')
        self.assertEqual(strip_presentation_noise('Api v1 companies list'), 'companies list')

    def test_ensure_service_first_title(self):
        self.assertEqual(
            ensure_service_first_title('List buckets', tool_name='storage_list_buckets'),
            'Storage: List buckets',
        )
        self.assertEqual(
            ensure_service_first_title('Storage: List buckets', tool_name='storage_list_buckets'),
            'Storage: List buckets',
        )
        self.assertEqual(
            ensure_service_first_title('List users (Acme)', tool_name='identity_list_users'),
            'Identity: List users (Acme)',
        )

    def test_apply_gateway_tool_presentation(self):
        tool = apply_gateway_tool_presentation(
            {
                'name': 'email_list_messages',
                'title': 'API V1 List messages',
                'description': 'API V1 mailbox listing for /api/v1/messages/.',
            },
            company_label='Acme',
        )
        self.assertEqual(tool['title'], 'Email: List messages (Acme)')
        self.assertNotIn('API V1', tool['title'])
        self.assertNotIn('/api/v1/', tool['description'])
        self.assertIn('company Acme', tool['description'])

    def test_annotations_from_method(self):
        op = {'operationId': 'api_v1_templates_list', 'x-mcp': {'read_only': True}}
        ann = tool_annotations(op, method='get', access={'read_only': True, 'destructive': False})
        self.assertTrue(ann['readOnlyHint'])
        self.assertFalse(ann['destructiveHint'])

    def test_delete_is_idempotent(self):
        op = {'operationId': 'api_v1_users_destroy'}
        ann = tool_annotations(op, method='delete', access={'read_only': False, 'destructive': True})
        self.assertTrue(ann['destructiveHint'])
        self.assertTrue(ann['idempotentHint'])

    def test_apply_tool_presentation_from_openapi(self):
        operation = {
            'summary': 'List templates',
            'description': 'Returns template rows for the company. Safe to retry.',
            'x-mcp': {'read_only': True},
            'responses': {
                '200': {
                    'content': {
                        'application/json': {
                            'schema': {'type': 'object', 'properties': {'results': {'type': 'array'}}},
                        }
                    }
                }
            },
        }
        tool = apply_tool_presentation(
            {'name': 'list_templates', 'inputSchema': {'type': 'object', 'properties': {}}},
            operation=operation,
            method='get',
            path='/api/v1/templates/',
            root={'components': {'schemas': {}}},
        )
        self.assertEqual(tool['title'], 'List templates')
        self.assertIn('template', tool['description'].lower())
        self.assertTrue(tool['annotations']['readOnlyHint'])
        self.assertIsInstance(tool.get('outputSchema'), dict)

    def test_gateway_instructions(self):
        text = shellui_gateway_instructions(title='Shellui AI MCP gateway', connected_services=['storage', 'ai'])
        self.assertIn('Shellui', text)
        self.assertNotIn('—', text)

    def test_apply_company_scope_to_tool(self):
        scoped = apply_company_scope_to_tool(
            {'title': 'List users', 'description': 'Lists users for the workspace.'},
            company_label='Acme',
        )
        self.assertEqual(scoped['title'], 'List users (Acme)')
        self.assertIn('company Acme', scoped['description'])
        self.assertIn('not from tool arguments', scoped['description'])

    def test_apply_tool_presentation_strips_api_version_from_title(self):
        operation = {
            'summary': 'API V1 List templates',
            'description': 'Returns template rows.',
            'x-mcp': {'read_only': True},
            'responses': {'200': {'description': 'ok'}},
        }
        tool = apply_tool_presentation(
            {'name': 'list_templates', 'inputSchema': {'type': 'object', 'properties': {}}},
            operation=operation,
            method='get',
            path='/api/v1/templates/',
            root={'components': {'schemas': {}}},
        )
        self.assertEqual(tool['title'], 'List templates')
