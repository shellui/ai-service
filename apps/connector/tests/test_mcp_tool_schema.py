"""MCP tool inputSchema must be strict-client safe (typed properties, no bare {})."""

from __future__ import annotations

from django.test import TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.connector.mcp_openapi_tools import tools_from_schema
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
        self.assertEqual(query_props['format']['type'], 'string')
        self.assertEqual(query_props['scope']['type'], 'string')
        self.assertEqual(audit_tool_input_schemas([fixed]), [])
