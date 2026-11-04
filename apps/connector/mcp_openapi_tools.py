"""Build MCP tool definitions from a drf-spectacular OpenAPI schema."""

from __future__ import annotations

from typing import Any

from shellui_django.mcp.openapi_mcp import tool_access_flags
from shellui_django.mcp.routing import path_parameter_names
from apps.connector.mcp_tool_naming import (
    ensure_unique_tool_names,
    legacy_slug_tool_name,
    resolve_mcp_tool_name,
    select_newest_api_version_operations,
)

from apps.connector.mcp_tool_presentation import apply_tool_presentation
from apps.connector.mcp_tool_schema import normalize_tool_input_schema, openapi_schema_to_json_schema


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
        prop = openapi_schema_to_json_schema(raw if isinstance(raw, dict) else {}, root)
        desc = str(param.get('description') or (raw.get('description') if isinstance(raw, dict) else '') or '').strip()
        if desc and not str(prop.get('description') or '').strip():
            prop['description'] = desc
        properties[key] = prop
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


def tools_from_schema(schema: dict[str, Any]) -> list[dict[str, Any]]:
    operations = select_newest_api_version_operations(schema)
    proposed_names = [resolve_mcp_tool_name(op, method, path) for path, method, op in operations]
    unique_names = ensure_unique_tool_names(proposed_names)
    tools: list[dict[str, Any]] = []
    for (path, method, operation), name in zip(operations, unique_names, strict=True):
        legacy_name = legacy_slug_tool_name(method, path, operation.get('operationId'))
        description = (operation.get('summary') or operation.get('description') or name).strip()
        path_params = path_parameter_names(path)
        query_props, query_required = _parameter_schemas(operation, schema, location='query')
        body_props, body_required = _body_schemas(operation, schema)
        properties: dict[str, Any] = {
            'path': {'type': 'string', 'const': path, 'description': 'OpenAPI path for this MCP proxy call.'},
            'method': {
                'type': 'string',
                'enum': [method.upper()],
                'description': 'HTTP method for this MCP proxy call.',
            },
            'query': {
                'type': 'object',
                'additionalProperties': False,
                'properties': query_props,
                'description': 'Query string fields for this API operation.',
            },
            'body': {
                'type': 'object',
                'additionalProperties': False,
                'properties': body_props,
                'description': 'JSON body fields for this API operation.',
            },
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
                'properties': {
                    param: {
                        'type': 'string',
                        'description': f'Path parameter `{param}`.',
                    }
                    for param in path_params
                },
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
        tool = apply_tool_presentation(
            {
                'name': name,
                'description': description,
                'inputSchema': input_schema,
                '_meta': {
                    'path': path,
                    'method': method.upper(),
                    'operationId': operation.get('operationId'),
                    'legacy_tool_name': legacy_name,
                    'path_params': path_params,
                    'query_fields': sorted(query_props.keys()) or None,
                    'query_required': query_required or None,
                    'body_fields': sorted(body_props.keys()) or None,
                    'body_required': body_required or None,
                    'read_only': access['read_only'],
                    'destructive': access['destructive'],
                    'mcp_tagged': access['tagged'],
                    'has_json_response': bool(
                        isinstance(operation.get('responses'), dict)
                        and any(
                            isinstance((operation.get('responses') or {}).get(code), dict)
                            and isinstance(
                                ((operation.get('responses') or {}).get(code) or {}).get('content'), dict
                            )
                            and (
                                ((operation.get('responses') or {}).get(code) or {})
                                .get('content', {})
                                .get('application/json')
                            )
                            for code in ('200', '201', '202')
                        )
                    ),
                },
            },
            operation=operation,
            method=method,
            path=path,
            root=schema,
        )
        tools.append(tool)
    tools.sort(key=lambda t: t['name'])
    return tools
