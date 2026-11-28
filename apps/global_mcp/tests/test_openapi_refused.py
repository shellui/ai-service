"""Saas operations marked ``global_refused`` are never offered to an agent."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.global_mcp.openapi_tools import tools_from_openapi


def _document() -> dict:
    return {
        'paths': {
            '/api/v1/projects/': {
                'get': {'operationId': 'api_v1_projects_list', 'x-mcp': {'global_refused': False}},
            },
            '/api/v1/projects/{id}/': {
                'delete': {
                    'operationId': 'api_v1_projects_destroy',
                    'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
                    'x-mcp': {'destructive': True, 'global_refused': True},
                },
            },
            '/api/v1/projects/{id}/transfer-ownership/': {
                'post': {
                    'operationId': 'api_v1_projects_transfer_ownership_create',
                    'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
                    'x-mcp': {'global_refused': True},
                },
            },
        },
    }


class GlobalRefusedToolsTests(SimpleTestCase):
    def test_refused_operations_are_not_listed(self):
        names = {tool['name'] for tool in tools_from_openapi(_document())}
        self.assertIn('saas_list_projects', names)
        self.assertEqual(len(names), 1, names)
        self.assertFalse(any('delete_projects' in n or 'transfer' in n for n in names))
