"""MCP tool inputSchema must be strict-client safe (typed properties, no bare {})."""

from __future__ import annotations

from django.test import TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.connector.mcp_openapi_tools import tools_from_schema
from apps.connector.mcp_tenant import input_schema_has_tenant_fields
from apps.connector.mcp_tool_schema import audit_tool_input_schemas, normalize_mcp_tool, openapi_schema_to_json_schema


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

    def test_described_ref_allof_keeps_object_properties(self):
        root = {
            'components': {
                'schemas': {
                    'BroadcastAudience': {
                        'type': 'object',
                        'description': 'Who receives the broadcast.',
                        'required': ['mode'],
                        'properties': {
                            'mode': {
                                'type': 'string',
                                'enum': ['pick', 'newsletter'],
                                'description': 'How recipients are chosen.',
                            },
                            'emails': {
                                'type': 'array',
                                'description': 'Addresses outside the directory.',
                                'items': {'type': 'string', 'description': 'Email address.'},
                            },
                        },
                    }
                }
            }
        }
        converted = openapi_schema_to_json_schema(
            {
                'allOf': [{'$ref': '#/components/schemas/BroadcastAudience'}],
                'description': 'Defaults to the saved audience.',
            },
            root,
        )
        self.assertEqual(converted['type'], 'object')
        self.assertIn('mode', converted['properties'])
        self.assertIs(converted['additionalProperties'], False)
        self.assertNotIn('allOf', converted)
        self.assertNotIn('$ref', converted)

    def test_untyped_editor_fields_are_not_free_form_objects(self):
        from apps.connector.mcp_schema_inspector import inspect_tool

        body = {
            'type': 'object',
            'properties': {
                'document': {},
                'theme': {'description': 'Colors that repaint a library design.'},
                'translations': {'description': 'Other languages of the copy.'},
                'variables': {'description': 'Placeholder map for tokens.'},
                'first_name': {'type': 'string', 'description': 'Given name.'},
                'group_ids': {
                    'type': 'array',
                    'description': 'Manual group ids.',
                    'items': {'type': 'integer', 'description': 'Group id.'},
                },
                'data': {},
            },
        }
        converted = openapi_schema_to_json_schema(body, {'components': {'schemas': {}}})
        props = converted['properties']
        for name in ('document', 'theme', 'translations', 'variables', 'data'):
            self.assertIsNot(props[name].get('additionalProperties'), True, name)
            self.assertTrue(props[name].get('properties') or props[name].get('additionalProperties'), name)
        self.assertIn('type', props['document']['properties'])
        self.assertIn('colors', props['theme']['properties'])
        self.assertIn('fr', props['translations']['properties'])
        self.assertEqual(props['variables']['additionalProperties']['type'], 'string')
        self.assertIn('shelluiPreferences', props['data']['properties'])
        tool = normalize_mcp_tool(
            {
                'name': 'email_create_library',
                'description': 'Create a company email design from a document, theme, and translations.',
                'inputSchema': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'body': {
                            'type': 'object',
                            'description': 'JSON request body.',
                            'additionalProperties': False,
                            'properties': props,
                        }
                    },
                },
            }
        )
        categories = {issue.category for issue in inspect_tool('email', tool)}
        self.assertNotIn('broad_free_form_object', categories)
        self.assertNotIn('untyped_or_empty', categories)
        self.assertNotIn('missing_description', categories)

    def test_wire_catalog_recovers_operation_access_and_json_contracts(self):
        """shellui tools/list drops _meta and opens JSON fields. Normalization must undo both."""
        from apps.connector.mcp_approval_gate import tool_traits_from_export

        listed = {
            'name': 'storage_v1_bucket_empty_create',
            'description': 'Delete every object in a bucket.',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'path': {'type': 'string', 'const': '/storage/v1/bucket/{bucket_id}/empty'},
                    'method': {'type': 'string', 'enum': ['POST']},
                    'query': {'type': 'object', 'additionalProperties': False, 'properties': {}},
                    'body': {'type': 'object', 'additionalProperties': False, 'properties': {}},
                    'path_params': {
                        'type': 'object',
                        'additionalProperties': False,
                        'properties': {'bucket_id': {'type': 'string'}},
                        'required': ['bucket_id'],
                    },
                },
                'required': ['path', 'method', 'path_params'],
                'additionalProperties': False,
            },
        }
        fixed = normalize_mcp_tool(listed)
        self.assertEqual(fixed['_meta']['operationId'], 'storage_v1_bucket_empty_create')
        read_only, destructive = tool_traits_from_export(fixed, method='POST')
        self.assertFalse(read_only)
        self.assertTrue(destructive)
        self.assertTrue(fixed['annotations']['destructiveHint'])
        renamed = normalize_mcp_tool(
            {
                **listed,
                'name': 'storage_empty_bucket',
            }
        )
        read_only, destructive = tool_traits_from_export(renamed, method='POST')
        self.assertFalse(read_only)
        self.assertTrue(destructive)
        self.assertEqual(renamed['_meta']['operationId'], 'storage_v1_bucket_empty_create')

        preview = normalize_mcp_tool(
            {
                'name': 'api_v1_broadcasts_preview',
                'description': 'Render a broadcast without sending it to anyone.',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'path': {'type': 'string', 'const': '/api/v1/broadcasts/preview'},
                        'method': {'type': 'string', 'enum': ['POST']},
                    },
                    'required': ['path', 'method'],
                    'additionalProperties': False,
                },
            }
        )
        read_only, destructive = tool_traits_from_export(preview, method='POST')
        self.assertTrue(read_only)
        self.assertFalse(destructive)
        self.assertTrue(preview['annotations']['readOnlyHint'])

        document = normalize_mcp_tool(
            {
                'name': 'api_v1_library_create',
                'description': 'Create a company email design from a document and theme.',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'path': {'type': 'string', 'const': '/api/v1/library'},
                        'method': {'type': 'string', 'enum': ['POST']},
                        'body': {
                            'type': 'object',
                            'additionalProperties': False,
                            'properties': {
                                'document': {
                                    'type': 'object',
                                    'additionalProperties': True,
                                    'description': 'JSON value',
                                },
                            },
                        },
                    },
                    'required': ['path', 'method'],
                    'additionalProperties': False,
                },
            }
        )
        doc = document['inputSchema']['properties']['body']['properties']['document']
        self.assertIn('type', doc['properties'])
        self.assertIs(doc.get('additionalProperties'), False)

    def test_openapi_tools_never_expose_company_id(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = tools_from_schema(schema)
        violations: list[str] = []
        for tool in tools:
            paths = input_schema_has_tenant_fields(tool.get('inputSchema') or {})
            for path in paths:
                violations.append(f"{tool.get('name')} {path}")
        self.assertEqual(violations, [])
