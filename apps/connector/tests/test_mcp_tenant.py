"""MCP tools must not expose company_id; tenant is bound from the agent token."""

from __future__ import annotations

from django.test import TestCase

from apps.connector.mcp_openapi_tools import tools_from_schema
from apps.connector.mcp_tenant import (
    apply_tenant_to_arguments,
    company_label_from_claims,
    input_schema_has_tenant_fields,
    strip_tenant_fields_from_input_schema,
)
from apps.connector.mcp_tool_schema import normalize_mcp_tool
from shellui_django.mcp.routing import McpToolArgumentError


def _schema_with_company_query() -> dict:
    return {
        'paths': {
            '/api/v1/messages/': {
                'get': {
                    'operationId': 'api_v1_messages_list',
                    'tags': ['mcp-tools'],
                    'parameters': [
                        {'name': 'company_id', 'in': 'query', 'required': True, 'schema': {'type': 'integer'}},
                        {'name': 'mailbox', 'in': 'query', 'schema': {'type': 'string'}},
                    ],
                    'responses': {'200': {'description': 'ok'}},
                }
            }
        }
    }


class McpTenantTests(TestCase):
    def test_tools_from_schema_omits_company_id_from_input_schema(self):
        tools = tools_from_schema(_schema_with_company_query())
        self.assertEqual(len(tools), 1)
        tool = tools[0]
        query_props = tool['inputSchema']['properties']['query']['properties']
        self.assertNotIn('company_id', query_props)
        self.assertIn('mailbox', query_props)
        self.assertEqual(tool['_meta']['tenant_query_fields'], ['company_id'])
        self.assertEqual(input_schema_has_tenant_fields(tool['inputSchema']), [])

    def test_normalize_strips_company_id_from_legacy_remote_tool(self):
        legacy = {
            'name': 'list_messages',
            'description': 'List messages for the company mailbox.',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'path': {'type': 'string', 'const': '/api/v1/messages/'},
                    'method': {'type': 'string', 'enum': ['GET']},
                    'query': {
                        'type': 'object',
                        'additionalProperties': False,
                        'properties': {
                            'company_id': {'type': 'integer'},
                            'limit': {'type': 'integer'},
                        },
                        'required': ['company_id'],
                    },
                },
                'required': ['path', 'method'],
                'additionalProperties': False,
            },
        }
        fixed = normalize_mcp_tool(legacy)
        query_props = fixed['inputSchema']['properties']['query']['properties']
        self.assertNotIn('company_id', query_props)
        self.assertIn('limit', query_props)
        self.assertEqual(fixed['_meta']['tenant_query_fields'], ['company_id'])
        self.assertEqual(input_schema_has_tenant_fields(fixed['inputSchema']), [])

    def test_apply_tenant_injects_query_company_id(self):
        meta = {'tenant_query_fields': ['company_id']}
        args = apply_tenant_to_arguments({'query': {'mailbox': 'inbox'}}, {'company_id': 10}, meta)
        self.assertEqual(args['query']['company_id'], '10')
        self.assertEqual(args['query']['mailbox'], 'inbox')

    def test_apply_tenant_rejects_cross_company_override(self):
        meta = {'tenant_query_fields': ['company_id']}
        with self.assertRaises(McpToolArgumentError):
            apply_tenant_to_arguments({'query': {'company_id': 99}}, {'company_id': 10}, meta)

    def test_company_label_prefers_display_name_from_claims(self):
        self.assertEqual(
            company_label_from_claims({'company_id': 3, 'company_name': 'Acme'}),
            'Acme',
        )
        self.assertEqual(company_label_from_claims({'company_id': 3}), 'Company 3')

    def test_strip_tenant_fields_returns_binding(self):
        schema = {
            'type': 'object',
            'properties': {
                'path_params': {
                    'type': 'object',
                    'properties': {'company_id': {'type': 'string'}, 'id': {'type': 'string'}},
                    'required': ['company_id', 'id'],
                }
            },
        }
        binding = strip_tenant_fields_from_input_schema(schema)
        self.assertEqual(binding, {'path_params': ['company_id']})
        props = schema['properties']['path_params']['properties']
        self.assertNotIn('company_id', props)
        self.assertEqual(schema['properties']['path_params']['required'], ['id'])
