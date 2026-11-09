"""MCP tool inputSchema must be strict-client safe (typed properties, no bare {})."""

from __future__ import annotations

from django.test import TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.connector.mcp_openapi_tools import tools_from_schema
from apps.connector.mcp_tenant import input_schema_has_tenant_fields
from apps.connector.mcp_tool_schema import audit_tool_input_schemas, normalize_mcp_tool


@override_settings(
    SECRET_KEY='test-schema-audit',
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test',
    IDENTITY_ISSUER='http://localhost:8001',
    IDENTITY_JWKS_URL='http://localhost:8001/.well-known/jwks.json',
    STORAGE_SERVICE_URL='',
    HOSTING_SERVICE_URL='',
    EMAIL_SERVICE_URL='',
    SAAS_SERVICE_URL='',
)
class McpToolSchemaAuditTests(TestCase):
    def test_ai_service_openapi_tools_have_typed_input_schemas(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = tools_from_schema(schema)
        self.assertTrue(tools, 'expected at least one mcp-tools operation in OpenAPI schema')
        issues = audit_tool_input_schemas(tools)
        self.assertEqual(
            issues,
            [],
            'schema violations: ' + '; '.join(f'{name} {path}: {reason}' for name, path, reason in issues[:20]),
        )

    def test_normalize_repairs_legacy_empty_query_properties(self):
        legacy = {
            'name': 'legacy_tool',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'query': {
                        'type': 'object',
                        'additionalProperties': False,
                        'properties': {'format': {}, 'scope': {}},
                    }
                },
                'additionalProperties': False,
            },
        }
        fixed = normalize_mcp_tool(legacy)
        query_props = fixed['inputSchema']['properties']['query']['properties']
        # Untyped OpenAPI fragments (including empty ``{}``) become free-form objects so
        # JSONField body fields like ``document`` remain writable for MCP clients.
        self.assertEqual(query_props['format']['type'], 'object')
        self.assertTrue(query_props['format']['additionalProperties'])
        self.assertEqual(query_props['scope']['type'], 'object')
        self.assertTrue(query_props['scope']['additionalProperties'])
        self.assertEqual(audit_tool_input_schemas([fixed]), [])

    def test_untyped_json_field_becomes_object_not_string(self):
        from apps.connector.mcp_tool_schema import openapi_schema_to_json_schema

        self.assertEqual(
            openapi_schema_to_json_schema({}, {}),
            {
                'type': 'object',
                'additionalProperties': True,
                'description': 'JSON value (OpenAPI schema had no type).',
                'properties': {},
            },
        )
        themed = openapi_schema_to_json_schema({'description': 'Theme map'}, {})
        self.assertEqual(themed['type'], 'object')
        self.assertTrue(themed['additionalProperties'])
        self.assertEqual(themed['description'], 'Theme map')

    def test_normalize_recovers_operation_meta_from_proxy_schema(self):
        """Downstream tools/list strips ``_meta``; gateway must rebuild path/method for the gate."""
        legacy = {
            'name': 'api_v1_users_list',
            'description': 'List company users',
            'annotations': {
                'readOnlyHint': False,
                'destructiveHint': False,
                'idempotentHint': False,
                'openWorldHint': False,
            },
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'path': {'type': 'string', 'const': '/api/v1/users'},
                    'method': {'type': 'string', 'enum': ['GET']},
                    'query': {
                        'type': 'object',
                        'additionalProperties': False,
                        'properties': {'page': {'type': 'integer'}},
                    },
                    'body': {'type': 'object', 'additionalProperties': False, 'properties': {}},
                },
                'required': ['path', 'method'],
                'additionalProperties': False,
            },
        }
        fixed = normalize_mcp_tool(legacy)
        self.assertEqual(fixed['_meta']['path'], '/api/v1/users')
        self.assertEqual(fixed['_meta']['method'], 'GET')
        self.assertTrue(fixed['_meta']['read_only'])
        self.assertTrue(fixed['annotations']['readOnlyHint'])
        self.assertFalse(fixed['annotations']['destructiveHint'])

    def test_openapi_tools_never_expose_company_id(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = tools_from_schema(schema)
        violations: list[str] = []
        for tool in tools:
            paths = input_schema_has_tenant_fields(tool.get('inputSchema') or {})
            for path in paths:
                violations.append(f"{tool.get('name')} {path}")
        self.assertEqual(violations, [])
