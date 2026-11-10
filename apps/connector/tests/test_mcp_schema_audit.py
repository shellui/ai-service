"""Gateway schema gaps found by the per-service MCP audits."""

from __future__ import annotations

import json
from pathlib import Path

from django.test import SimpleTestCase

from apps.connector.mcp_agent_arguments import (
    coerce_call_arguments,
    http_headers_from_arguments,
    public_input_schema,
)
from apps.connector.mcp_approval_channel import CHANNEL_FORM, CHANNEL_LINK, approval_channel
from apps.connector.mcp_approval_gate import tool_traits_from_export
from apps.connector.mcp_discovery import describe_payload
from apps.connector.mcp_openapi_tools import tools_from_schema

OPENAPI = Path(__file__).resolve().parent / 'fixtures' / 'openapi'

_EMAIL_EVENT_TYPES = (
    'identity.auth.magic_link.requested',
    'identity.auth.password_reset.requested',
)


def _tool(schema: dict, name: str) -> dict:
    tools = tools_from_schema(schema)
    match = next(tool for tool in tools if tool['name'] == name)
    return match


def _email_templates_schema() -> dict:
    return {
        'openapi': '3.0.3',
        'paths': {
            '/api/v1/templates': {
                'get': {
                    'operationId': 'api_v1_templates_list',
                    'tags': ['mcp-tools'],
                    'x-mcp': {'tool_name': 'list_templates', 'read_only': True, 'destructive': False},
                    'parameters': [
                        {
                            'in': 'query',
                            'name': 'company_id',
                            'schema': {'type': 'integer'},
                        },
                        {
                            'in': 'query',
                            'name': 'event_type',
                            'required': False,
                            'description': 'Catalog event id.',
                            'schema': {
                                'type': 'string',
                                'enum': list(_EMAIL_EVENT_TYPES),
                                'description': 'Catalog event id.',
                            },
                        },
                        {
                            'in': 'query',
                            'name': 'scheduled_job_run_id',
                            'schema': {'type': 'integer', 'description': 'Staff only.'},
                        },
                    ],
                }
            }
        },
    }


def _saas_company_schema() -> dict:
    return {
        'openapi': '3.0.3',
        'paths': {
            '/saas/v1/companies/{company_id}': {
                'patch': {
                    'operationId': 'saas_v1_companies_partial_update',
                    'tags': ['mcp-tools'],
                    'x-mcp': {'tool_name': 'update_companies', 'read_only': False, 'destructive': False},
                    'parameters': [
                        {
                            'in': 'path',
                            'name': 'company_id',
                            'required': True,
                            'schema': {'type': 'integer'},
                        },
                        {
                            'in': 'header',
                            'name': 'Idempotency-Key',
                            'schema': {'type': 'string', 'minLength': 8, 'description': 'Retry key for this update.'},
                        },
                        {
                            'in': 'header',
                            'name': 'Authorization',
                            'schema': {'type': 'string'},
                        },
                    ],
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'region': {
                                            'type': 'string',
                                            'enum': ['eu', 'us'],
                                            'default': 'eu',
                                            'description': 'Data region for the company.',
                                        },
                                        'seat_count': {
                                            'type': 'integer',
                                            'minimum': 1,
                                            'maximum': 500,
                                        },
                                    },
                                    'required': ['region'],
                                }
                            }
                        }
                    },
                }
            }
        },
    }


class SchemaAuditTests(SimpleTestCase):
    def test_path_parameters_keep_format_enum_and_description(self):
        schema = json.loads((OPENAPI / 'hosting.json').read_text(encoding='utf-8'))
        tool = _tool(schema, 'create_apps_deployments_finalize')
        node = tool['inputSchema']['properties']['path_params']['properties']['deployment_id']
        self.assertEqual(node.get('format'), 'uuid')
        self.assertIn('UUID', node.get('description') or '')
        public = public_input_schema(tool['inputSchema'])
        self.assertEqual(public['properties']['deployment_id'].get('format'), 'uuid')
        self.assertNotIn('company_id', public['properties'])
        deliveries = _tool(schema, 'list_action_deliveries')
        deliveries_public = public_input_schema(deliveries['inputSchema'])
        self.assertNotIn('scheduled_job_run_id', deliveries_public['properties'])
        self.assertNotIn('company_id', deliveries_public['properties'])

    def test_email_event_type_enum_survives_describe(self):
        tool = _tool(_email_templates_schema(), 'list_templates')
        tool = {**tool, 'name': 'email_list_templates', '_meta': {**tool['_meta'], 'read_only': True}}
        public = public_input_schema(tool['inputSchema'])
        event = public['properties']['event_type']
        self.assertEqual(event['enum'], list(_EMAIL_EVENT_TYPES))
        self.assertNotIn('scheduled_job_run_id', public['properties'])
        self.assertNotIn('company_id', public['properties'])
        described = describe_payload([tool], {'name': 'email_list_templates'}, access_mode='ask')
        described_enum = described['tools'][0]['inputSchema']['properties']['event_type']['enum']
        self.assertEqual(described_enum, list(_EMAIL_EVENT_TYPES))

    def test_saas_region_enum_and_header_and_form_channel(self):
        tool = _tool(_saas_company_schema(), 'update_companies')
        tool = {**tool, 'name': 'saas_update_companies'}
        public = public_input_schema(tool['inputSchema'])
        self.assertEqual(public['properties']['region']['enum'], ['eu', 'us'])
        self.assertEqual(public['properties']['region']['default'], 'eu')
        self.assertEqual(public['properties']['seat_count']['minimum'], 1)
        self.assertEqual(public['properties']['seat_count']['maximum'], 500)
        self.assertIn('region', public['required'])
        self.assertIn('idempotency_key', public['properties'])
        self.assertNotIn('authorization', {key.lower() for key in public['properties']})
        self.assertNotIn('company_id', public['properties'])
        read_only, destructive = tool_traits_from_export(tool, method='PATCH')
        self.assertFalse(read_only)
        self.assertFalse(destructive)
        self.assertEqual(
            approval_channel(destructive=destructive, company_id=10, form_supported=True),
            CHANNEL_FORM,
        )
        coerced = coerce_call_arguments(
            {'region': 'us', 'idempotency_key': 'retry-1', 'method': 'DELETE', 'path': '/evil'},
            tool['inputSchema'],
            tool['_meta'],
        )
        self.assertEqual(coerced['method'], 'PATCH')
        self.assertEqual(coerced['body']['region'], 'us')
        self.assertEqual(coerced['headers']['Idempotency-Key'], 'retry-1')
        self.assertEqual(http_headers_from_arguments(coerced), {'Idempotency-Key': 'retry-1'})
        described = describe_payload([tool], {'name': 'saas_update_companies'}, access_mode='ask')
        region = described['tools'][0]['inputSchema']['properties']['region']
        self.assertEqual(region['enum'], ['eu', 'us'])
        self.assertIn('region', described['tools'][0]['inputSchema']['required'])

    def test_hosting_finalize_is_destructive_link_channel(self):
        schema = json.loads((OPENAPI / 'hosting.json').read_text(encoding='utf-8'))
        tool = _tool(schema, 'create_apps_deployments_finalize')
        tool = {**tool, 'name': 'hosting_create_apps_deployments_finalize'}
        _read_only, destructive = tool_traits_from_export(tool, method='POST')
        self.assertTrue(destructive)
        self.assertEqual(
            approval_channel(destructive=True, company_id=10, form_supported=True),
            CHANNEL_LINK,
        )

    def test_storage_upsert_header_is_an_agent_argument(self):
        schema = json.loads((OPENAPI / 'storage.json').read_text(encoding='utf-8'))
        tool = _tool(schema, 'create_object')
        public = public_input_schema(tool['inputSchema'])
        self.assertIn('x_upsert', public['properties'])
        coerced = coerce_call_arguments(
            {'x_upsert': 'true'},
            tool['inputSchema'],
            tool['_meta'],
        )
        self.assertEqual(http_headers_from_arguments(coerced)['x-upsert'], 'true')


