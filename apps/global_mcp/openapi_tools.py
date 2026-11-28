"""Build saas MCP tools from the saas OpenAPI document and call them over HTTP."""

from __future__ import annotations

import copy
import re
from typing import Any
from urllib.parse import quote

from django.core.cache import cache

from apps.connector.mcp_discovery import redact_arguments
from apps.global_mcp.saas_client import SaasError, request_json

_CACHE_KEY = 'global_mcp:saas_openapi'
_CACHE_SECONDS = 60
_METHODS = ('get', 'post', 'put', 'patch', 'delete')

_ACTION_SUFFIXES: tuple[tuple[str, str], ...] = (
    ('partial_update', 'update'),
    ('retrieve', 'get'),
    ('destroy', 'delete'),
    ('create', 'create'),
    ('list', 'list'),
    ('update', 'update'),
)


def tool_name_for(operation_id: str, explicit: str = '') -> str:
    if explicit:
        return explicit
    tokens = [part for part in re.sub(r'[^a-zA-Z0-9_]+', '_', operation_id).lower().split('_') if part]
    while tokens and (tokens[0] in {'api', 'service'} or re.fullmatch(r'v\d+', tokens[0] or '')):
        tokens.pop(0)
    stripped = '_'.join(tokens)
    for suffix, verb in _ACTION_SUFFIXES:
        if stripped == suffix:
            local = verb
            break
        needle = f'_{suffix}'
        if stripped.endswith(needle):
            resource = stripped[: -len(needle)]
            local = f'{verb}_{resource}' if resource else verb
            break
    else:
        local = stripped or 'call'
    if local.startswith('saas_'):
        return local
    return f'saas_{local}'


def _extension(operation: dict) -> dict | None:
    raw = operation.get('x-mcp')
    if isinstance(raw, dict):
        return raw
    nested = (operation.get('extensions') or {}).get('x-mcp')
    return nested if isinstance(nested, dict) else None


def _resolve_ref(schema: dict, node: Any) -> Any:
    if not isinstance(node, dict):
        return node
    ref = node.get('$ref')
    if isinstance(ref, str) and ref.startswith('#/'):
        cursor: Any = schema
        for part in ref[2:].split('/'):
            if not isinstance(cursor, dict):
                return node
            cursor = cursor.get(part)
        return _resolve_ref(schema, cursor if isinstance(cursor, dict) else node)
    return node


def _input_schema(document: dict, operation: dict) -> dict:
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict):
            continue
        param = _resolve_ref(document, param)
        if not isinstance(param, dict) or param.get('in') not in {'path', 'query'}:
            continue
        name = str(param.get('name') or '')
        if not name:
            continue
        schema = _resolve_ref(document, param.get('schema') or {'type': 'string'})
        properties[name] = schema if isinstance(schema, dict) else {'type': 'string'}
        if param.get('required'):
            required.append(name)
    body = operation.get('requestBody') or {}
    if isinstance(body, dict):
        content = (body.get('content') or {}).get('application/json') or {}
        schema = _resolve_ref(document, content.get('schema') or {})
        if isinstance(schema, dict) and schema.get('type') == 'object':
            for key, value in (schema.get('properties') or {}).items():
                properties[str(key)] = value if isinstance(value, dict) else {'type': 'string'}
            for key in schema.get('required') or []:
                if key not in required:
                    required.append(str(key))
    return {
        'type': 'object',
        'properties': properties,
        'required': required,
        'additionalProperties': False,
    }


def tools_from_openapi(document: dict) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    paths = document.get('paths') or {}
    if not isinstance(paths, dict):
        return []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            ext = _extension(operation)
            if not ext:
                continue
            if ext.get('global_refused') is True:
                # Refused for every agent (project deletion, ownership transfer): never listed or callable.
                continue
            operation_id = str(operation.get('operationId') or '')
            name = tool_name_for(operation_id, str(ext.get('name') or ''))
            description = str(operation.get('description') or operation.get('summary') or name)
            if name == 'saas_delete_companies' and ext.get('global_description'):
                description = str(ext['global_description'])
            read_only = bool(ext.get('read_only', method == 'get'))
            destructive = bool(ext.get('destructive'))
            found.append(
                {
                    'name': name,
                    'description': description,
                    'inputSchema': _input_schema(document, operation),
                    'annotations': {
                        'readOnlyHint': read_only and not destructive,
                        'destructiveHint': destructive,
                        'idempotentHint': read_only,
                        'openWorldHint': False,
                    },
                    '_meta': {
                        'service': 'saas',
                        'operationId': operation_id,
                        'method': method.upper(),
                        'path': path,
                        'read_only': read_only,
                        'destructive': destructive,
                        'sensitive': bool(ext.get('sensitive')),
                    },
                }
            )
    found.sort(key=lambda item: item['name'])
    return found


def load_saas_tools() -> list[dict[str, Any]]:
    cached = cache.get(_CACHE_KEY)
    if isinstance(cached, list):
        return cached
    tools = tools_from_openapi(_fetch_schema())
    cache.set(_CACHE_KEY, tools, _CACHE_SECONDS)
    return tools


def store_schema(document: dict) -> list[dict[str, Any]]:
    tools = tools_from_openapi(document)
    cache.set(_CACHE_KEY, tools, _CACHE_SECONDS)
    return tools


def _fetch_schema() -> dict:
    """Schema is public on saas. No agent token."""
    import requests

    from apps.global_mcp.resources import saas_base

    base = saas_base()
    if not base:
        return {}
    response = requests.get(f'{base}/api/schema/', timeout=5)
    if response.status_code >= 400:
        return {}
    try:
        return response.json()
    except ValueError:
        return {}


def public_tool(tool: dict) -> dict:
    """What an agent sees: no private ``_meta`` and no ``x-mcp-destination``.

    The saas OpenAPI schemas are copied verbatim, marker included. The company gateway removes it with
    ``client_tool``, and this uses the same function so the two endpoints cannot drift apart.
    """
    from apps.connector.mcp_discovery import client_tool

    return client_tool(tool)


def find_tool(tools: list[dict], name: str) -> dict | None:
    for tool in tools:
        if tool.get('name') == name:
            return tool
    return None


def quote_path_param(value: object) -> str:
    text = str(value)
    if text == '' or any(ord(char) < 32 for char in text):
        raise SaasError(400, None, 'Tool path is not allowed.')
    return quote(text, safe='').replace('.', '%2E')


def fill_tool_path(template: str, args: dict) -> str:
    """Percent-encode path parameters and keep the path on the template."""
    if (
        not template.startswith('/')
        or '://' in template
        or template.startswith('//')
        or any(char in template for char in ('\\', '?', '\r', '\n', '\t', ' ', '#'))
    ):
        raise SaasError(400, None, 'Tool path is not allowed.')
    filled_parts: list[str] = []
    for part in template.split('/'):
        if part.startswith('{') and part.endswith('}') and part.count('{') == 1 and part.count('}') == 1:
            name = part[1:-1]
            if not name or name not in args:
                raise SaasError(400, None, f'Missing {name or "path parameter"}.')
            filled_parts.append(quote_path_param(args.pop(name)))
            continue
        if '{' in part or '}' in part or part in {'.', '..'}:
            raise SaasError(400, None, 'Tool path is not allowed.')
        filled_parts.append(part)
    filled = '/'.join(filled_parts)
    if not filled.startswith('/') or any(part in {'.', '..'} for part in filled.split('/')):
        raise SaasError(400, None, 'Tool path is not allowed.')
    return filled


def call_saas_tool(tool: dict, arguments: dict, *, token: str) -> tuple[int, Any]:
    meta = tool.get('_meta') or {}
    method = str(meta.get('method') or 'GET')
    args = dict(arguments or {})
    path = fill_tool_path(str(meta.get('path') or ''), args)
    query: dict[str, Any] = {}
    headers: dict[str, str] = {}
    if 'idempotency_key' in args:
        headers['Idempotency-Key'] = str(args.pop('idempotency_key'))
    body = None
    if method in {'GET', 'DELETE'}:
        query = args
    else:
        body = args
    return request_json(method, path, token=token, query=query or None, body=body, headers=headers or None)


def redacted_arguments(arguments: dict) -> dict:
    redacted = redact_arguments(arguments)
    return redacted if isinstance(redacted, dict) else {}


def tool_copy(tool: dict) -> dict:
    return copy.deepcopy(tool)
