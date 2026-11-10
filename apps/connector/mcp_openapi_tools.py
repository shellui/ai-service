"""Build MCP tool definitions from a drf-spectacular OpenAPI schema."""

from __future__ import annotations

import re
from typing import Any

from shellui_django.mcp.openapi_mcp import is_destructive_operation, mcp_extension
from shellui_django.mcp.routing import path_parameter_names
from apps.connector.mcp_tool_naming import (
    ensure_unique_tool_names,
    legacy_slug_tool_name,
    resolve_mcp_tool_name,
    select_newest_api_version_operations,
)

from apps.connector.mcp_tenant import is_hidden_agent_field, is_tenant_field, partition_field_names
from apps.connector.mcp_tool_presentation import apply_tool_presentation
from apps.connector.mcp_tool_schema import normalize_tool_input_schema, openapi_schema_to_json_schema

# Headers the agent must never set. The gateway already sends Authorization.
_AUTH_HEADER_NAMES = frozenset({'authorization', 'cookie', 'proxy-authorization'})


def agent_header_argument_name(header_name: str) -> str:
    """``Idempotency-Key`` and ``x-upsert`` become argument names."""
    return re.sub(r'[^a-z0-9]+', '_', str(header_name).strip().lower()).strip('_')


def access_flags_from_operation(operation: dict[str, Any], method: str) -> dict[str, bool]:
    """Read ``x-mcp`` first. Do not treat PATCH or PUT as destructive.

    A missing ``x-mcp`` block still honors a ``destructive`` tag. DELETE stays
    destructive unless the operation is explicitly read-only.
    """
    verb = str(method or '').upper()
    ext = mcp_extension(operation)
    if ext is not None:
        read_only = bool(ext.get('read_only'))
        destructive = bool(ext.get('destructive'))
    else:
        read_only = False
        destructive = is_destructive_operation(operation)
    if verb in {'GET', 'HEAD', 'OPTIONS'}:
        read_only = True
    if read_only and verb != 'DELETE':
        destructive = False
    elif verb == 'DELETE':
        destructive = True
    return {'read_only': read_only, 'destructive': destructive, 'tagged': ext is not None}


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


def _header_parameters(
    operation: dict[str, Any],
    root: dict[str, Any],
) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    """Non-auth headers as agent arguments. Returns props, required args, arg -> header name."""
    properties: dict[str, Any] = {}
    required: list[str] = []
    names: dict[str, str] = {}
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('in') != 'header':
            continue
        header_name = str(param.get('name') or '').strip()
        if not header_name or header_name.lower() in _AUTH_HEADER_NAMES:
            continue
        arg = agent_header_argument_name(header_name)
        if not arg or is_hidden_agent_field(arg) or arg in properties:
            continue
        raw = param.get('schema') if isinstance(param.get('schema'), dict) else {'type': 'string'}
        prop = openapi_schema_to_json_schema(raw, root)
        desc = str(param.get('description') or '').strip()
        if desc and not str(prop.get('description') or '').strip():
            prop['description'] = desc
        if not str(prop.get('description') or '').strip():
            prop['description'] = f'Value for the {header_name} header.'
        properties[arg] = prop
        names[arg] = header_name
        if param.get('required'):
            required.append(arg)
    return properties, required, names


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
        op_summary = (operation.get('summary') or operation.get('description') or '').strip()
        description = op_summary or name
        path_params = path_parameter_names(path)
        path_props, _path_required = _parameter_schemas(operation, schema, location='path')
        query_props, query_required = _parameter_schemas(operation, schema, location='query')
        body_props, body_required = _body_schemas(operation, schema)
        header_props, header_required, header_names = _header_parameters(operation, schema)
        agent_path_params, tenant_path_params = partition_field_names(path_params)
        agent_path_params = [param for param in agent_path_params if not is_hidden_agent_field(param)]
        agent_query_props = {k: v for k, v in query_props.items() if not is_hidden_agent_field(str(k))}
        tenant_query_fields = [str(k) for k in query_props if is_tenant_field(str(k))]
        agent_query_required = [k for k in query_required if k in agent_query_props]
        agent_body_props = {k: v for k, v in body_props.items() if not is_hidden_agent_field(str(k))}
        tenant_body_fields = [str(k) for k in body_props if is_tenant_field(str(k))]
        agent_body_required = [k for k in body_required if k in agent_body_props]
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
                'properties': agent_query_props,
                'description': 'Query string fields for this API operation.',
            },
            'body': {
                'type': 'object',
                'additionalProperties': False,
                'properties': agent_body_props,
                'description': 'JSON body fields for this API operation.',
            },
        }
        if agent_query_required:
            properties['query']['required'] = agent_query_required
        if agent_body_required:
            properties['body']['required'] = agent_body_required
        required = ['path', 'method']
        if agent_path_params:
            path_properties: dict[str, Any] = {}
            for param in agent_path_params:
                documented = path_props.get(param)
                if isinstance(documented, dict) and documented:
                    path_properties[param] = documented
                else:
                    path_properties[param] = {
                        'type': 'string',
                        'description': f'Path parameter `{param}`.',
                    }
            properties['path_params'] = {
                'type': 'object',
                'additionalProperties': False,
                'properties': path_properties,
                'required': agent_path_params,
            }
            required.append('path_params')
        if header_props:
            properties['headers'] = {
                'type': 'object',
                'additionalProperties': False,
                'properties': header_props,
                'description': 'HTTP headers for this API operation.',
            }
            if header_required:
                properties['headers']['required'] = header_required
        access = access_flags_from_operation(operation, method)
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
                    'operation_summary': op_summary[:500] if op_summary else None,
                    'operationId': operation.get('operationId'),
                    'legacy_tool_name': legacy_name,
                    'path_params': path_params,
                    'tenant_path_params': tenant_path_params or None,
                    'query_fields': sorted(agent_query_props.keys()) or None,
                    'tenant_query_fields': tenant_query_fields or None,
                    'query_required': agent_query_required or None,
                    'body_fields': sorted(agent_body_props.keys()) or None,
                    'tenant_body_fields': tenant_body_fields or None,
                    'body_required': agent_body_required or None,
                    'header_names': header_names or None,
                    'header_required': header_required or None,
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
