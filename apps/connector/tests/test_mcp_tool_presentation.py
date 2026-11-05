from django.test import SimpleTestCase

from apps.connector.mcp_tool_presentation import (
    apply_company_scope_to_tool,
    apply_tool_presentation,
    sanitize_shellui_copy,
    shellui_gateway_instructions,
    tool_annotations,
)


class McpToolPresentationTests(SimpleTestCase):
    def test_sanitize_shellui_copy(self):
        self.assertEqual(sanitize_shellui_copy('shellui — test'), 'Shellui, test')

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
