"""Agents see named arguments, not HTTP method and path."""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from apps.connector.mcp_agent_arguments import (
    DESCRIBE_PAYLOAD_BUDGET,
    DESCRIBE_SCHEMA_BUDGET,
    coerce_call_arguments,
    public_input_schema,
    trim_input_schema,
)
from apps.connector.mcp_discovery import describe_payload, search_payload


_SCHEMA = {
    'type': 'object',
    'properties': {
        'path': {'type': 'string', 'const': '/api/v1/templates'},
        'method': {'type': 'string', 'enum': ['GET']},
        'query': {
            'type': 'object',
            'properties': {
                'event_type': {
                    'type': 'string',
                    'enum': ['identity.auth.magic_link.requested', 'identity.auth.password_reset.requested'],
                    'description': 'Event that selects the template.',
                }
            },
            'required': ['event_type'],
        },
        'body': {'type': 'object', 'properties': {}},
    },
    'required': ['path', 'method', 'query'],
}


class AgentArgumentTests(SimpleTestCase):
    def test_public_schema_flattens_enum_and_drops_http_fields(self):
        public = public_input_schema(_SCHEMA)
        self.assertNotIn('path', public['properties'])
        self.assertNotIn('method', public['properties'])
        self.assertEqual(public['required'], ['event_type'])
        self.assertEqual(
            public['properties']['event_type']['enum'][0],
            'identity.auth.magic_link.requested',
        )

    def test_client_method_and_path_are_replaced_from_the_registry(self):
        flat = coerce_call_arguments(
            {'method': 'DELETE', 'path': '/evil', 'event_type': 'identity.auth.magic_link.requested'},
            _SCHEMA,
            {'method': 'GET', 'path': '/api/v1/templates'},
        )
        self.assertEqual(flat['method'], 'GET')
        self.assertEqual(flat['path'], '/api/v1/templates')
        self.assertEqual(flat['query']['event_type'], 'identity.auth.magic_link.requested')

    def test_legacy_query_object_still_forwards(self):
        legacy = coerce_call_arguments(
            {'query': {'event_type': 'identity.auth.magic_link.requested'}},
            _SCHEMA,
            {'method': 'get', 'path': '/api/v1/templates'},
        )
        self.assertEqual(legacy['method'], 'GET')
        self.assertEqual(legacy['query']['event_type'], 'identity.auth.magic_link.requested')

    def test_describe_schema_stays_inside_the_budget_and_keeps_enum(self):
        huge = {
            'type': 'object',
            'properties': {
                'path': {'type': 'string', 'const': '/api/v1/templates'},
                'method': {'type': 'string', 'enum': ['GET']},
                'query': {
                    'type': 'object',
                    'properties': {
                        'event_type': {
                            'type': 'string',
                            'description': 'x' * 20000,
                            'enum': [f'event.{i}' for i in range(80)],
                        }
                    },
                },
            },
            'required': ['path', 'method'],
        }
        tool = {
            'name': 'email_list_templates',
            'description': 'List templates. ' + ('y' * 5000),
            'inputSchema': huge,
            '_meta': {'method': 'GET', 'read_only': True, 'destructive': False},
            'annotations': {'readOnlyHint': True, 'destructiveHint': False},
        }
        described = describe_payload([tool], {'name': 'email_list_templates'}, access_mode='ask')
        encoded = json.dumps(described['tools'], sort_keys=True)
        self.assertLessEqual(len(encoded), DESCRIBE_PAYLOAD_BUDGET)
        schema = described['tools'][0]['inputSchema']
        self.assertLessEqual(len(json.dumps(schema, sort_keys=True)), DESCRIBE_SCHEMA_BUDGET + 400)
        self.assertIn('event.0', schema['properties']['event_type']['enum'])
        self.assertNotIn('path', schema['properties'])
        searched = search_payload([tool], {'query': 'email_list_templates', 'limit': 5}, access_mode='ask')
        row = searched['matches'][0]
        self.assertEqual(
            set(row),
            {'name', 'description', 'read_only', 'destructive', 'needs_approval'},
        )
        self.assertLessEqual(len(row['description']), 180)
        trimmed = trim_input_schema(huge)
        self.assertLessEqual(len(json.dumps(trimmed, sort_keys=True)), DESCRIBE_SCHEMA_BUDGET)
