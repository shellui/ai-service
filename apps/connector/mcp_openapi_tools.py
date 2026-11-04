"""Build MCP tool definitions from a drf-spectacular OpenAPI schema."""

from __future__ import annotations

import re
from typing import Any

from shellui_django.mcp.openapi_mcp import tool_access_flags
from shellui_django.mcp.routing import path_parameter_names

from apps.connector.mcp_tool_schema import normalize_tool_input_schema, openapi_schema_to_json_schema

MCP_TOOL_TAG = 'mcp-tools'


def _parameter_schemas(
    operation: dict[str, Any],
    root: dict[str, Any],
    *,
    location: str,
) -> tuple[dict[str, Any], list[str]]:
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('in') != location:
            continue
        name = param.get('name')
        if not name:
            continue
        key = str(name)
        raw = param.get('schema') if isinstance(param.get('schema'), dict) else param
        properties[key] = openapi_schema_to_json_schema(raw if isinstance(raw, dict) else {}, root)
        if param.get('required'):
            required.append(key)
    return properties, required


def _body_schemas(operation: dict[str, Any], root: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    request_body = operation.get('requestBody') or {}
    if not isinstance(request_body, dict):
        return {}, []
    content = request_body.get('content') or {}
    schema = content.get('application/json', {}).get('schema') or {}
    if not isinstance(schema, dict):
        return {}, []
    resolved = openapi_schema_to_json_schema(schema, root)
    if resolved.get('type') == 'object' and isinstance(resolved.get('properties'), dict):
        props = resolved['properties']
        required_raw = resolved.get('required') or []
        required = [str(k) for k in required_raw if str(k) in props]
        return props, required
    return {}, []


def _slug_tool_name(method: str, path: str, operation_id: str | None) -> str:
    if operation_id:
        base = re.sub(r'[^a-zA-Z0-9_]+', '_', operation_id).strip('_').lower()
        if base:
            return base[:120]
    cleaned = re.sub(r'[^a-zA-Z0-9_]+', '_', f'{method}_{path}').strip('_').lower()
    return cleaned[:120]


def tools_from_schema(schema: dict[str, Any]) -> list[dict[str, Any]]:
    paths = schema.get('paths') or {}
    tools: list[dict[str, Any]] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {'get', 'post', 'put', 'patch', 'delete'}:
                continue
            if not isinstance(operation, dict):
                continue
            tags = operation.get('tags') or []
            if MCP_TOOL_TAG not in tags:
                continue
            name = _slug_tool_name(method, path, operation.get('operationId'))
            description = (operation.get('summary') or operation.get('description') or name).strip()
            path_params = path_parameter_names(path)
            query_props, query_required = _parameter_schemas(operation, schema, location='query')
            body_props, body_required = _body_schemas(operation, schema)
            properties: dict[str, Any] = {
                'path': {'type': 'string', 'const': path},
                'method': {'type': 'string', 'enum': [method.upper()]},
                'query': {'type': 'object', 'additionalProperties': False, 'properties': query_props},
                'body': {'type': 'object', 'additionalProperties': False, 'properties': body_props},
            }
            if query_required:
                properties['query']['required'] = query_required
            if body_required:
                properties['body']['required'] = body_required
            required = ['path', 'method']
            if path_params:
                properties['path_params'] = {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {param: {'type': 'string'} for param in path_params},
                    'required': path_params,
                }
                required.append('path_params')
            access = tool_access_flags(operation)
            input_schema = normalize_tool_input_schema(
                {
                    'type': 'object',
                    'properties': properties,
                    'required': required,
                    'additionalProperties': False,
                },
                schema,
            )
            tools.append(
                {
                    'name': name,
                    'description': description,
                    'inputSchema': input_schema,
                    '_meta': {
                        'path': path,
                        'method': method.upper(),
                        'operationId': operation.get('operationId'),
                        'path_params': path_params,
                        'query_fields': sorted(query_props.keys()) or None,
                        'query_required': query_required or None,
                        'body_fields': sorted(body_props.keys()) or None,
                        'body_required': body_required or None,
                        'read_only': access['read_only'],
                        'destructive': access['destructive'],
                        'mcp_tagged': access['tagged'],
                    },
                }
            )
    tools.sort(key=lambda t: t['name'])
    return tools
