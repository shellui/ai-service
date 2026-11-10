"""Agent-facing tool arguments.

Downstream MCP tools are HTTP proxies. Their raw ``inputSchema`` requires ``path``
and ``method`` and nests real fields under ``query``, ``body``, and ``path_params``.
Agents must not invent those HTTP fields. The gateway shows a flat schema and, on
``tools/call``, rebuilds the proxy envelope from the registry.
"""

from __future__ import annotations

import copy
import json
from typing import Any

SEARCH_DESCRIPTION_MAX = 180
DESCRIBE_SCHEMA_BUDGET = 1200
DESCRIBE_PAYLOAD_BUDGET = 6000

_PROXY_KEYS = ('path', 'method', 'query', 'body', 'path_params', 'headers')
_SECTIONS = ('path_params', 'query', 'body', 'headers')


def one_line(text: object, *, limit: int = SEARCH_DESCRIPTION_MAX) -> str:
    collapsed = ' '.join(str(text or '').split())
    if len(collapsed) <= limit:
        return collapsed
    if limit <= 3:
        return collapsed[:limit]
    return collapsed[: limit - 3].rstrip() + '...'


def is_proxy_input_schema(schema: dict[str, Any] | None) -> bool:
    if not isinstance(schema, dict):
        return False
    props = schema.get('properties')
    if not isinstance(props, dict):
        return False
    return 'path' in props and 'method' in props


def _section(schema: dict[str, Any], name: str) -> tuple[dict[str, Any], list[str]]:
    props = schema.get('properties')
    section = props.get(name) if isinstance(props, dict) else None
    if not isinstance(section, dict):
        return {}, []
    inner = section.get('properties') if isinstance(section.get('properties'), dict) else {}
    required = [str(key) for key in section.get('required') or [] if str(key) in inner]
    return inner, required


def public_input_schema(schema: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten a proxy schema. Non-proxy schemas are returned unchanged."""
    if not isinstance(schema, dict):
        return {'type': 'object', 'properties': {}, 'additionalProperties': False}
    if not is_proxy_input_schema(schema):
        return copy.deepcopy(schema)
    from apps.connector.mcp_tenant import is_hidden_agent_field

    properties: dict[str, Any] = {}
    required: list[str] = []
    for section in _SECTIONS:
        inner, section_required = _section(schema, section)
        for key, node in inner.items():
            if key in properties or key in {'path', 'method'} or is_hidden_agent_field(key):
                continue
            properties[key] = copy.deepcopy(node)
        for key in section_required:
            if key in properties and key not in required:
                required.append(key)
    out: dict[str, Any] = {
        'type': 'object',
        'additionalProperties': False,
        'properties': properties,
    }
    if required:
        out['required'] = required
    return out


def _registry_method(schema: dict[str, Any], meta: dict[str, Any]) -> str:
    method = str(meta.get('method') or '').strip().upper()
    if method:
        return method
    node = (schema.get('properties') or {}).get('method') if isinstance(schema.get('properties'), dict) else None
    if isinstance(node, dict):
        enum = node.get('enum')
        if isinstance(enum, list) and enum:
            return str(enum[0]).strip().upper()
        const = node.get('const')
        if isinstance(const, str) and const.strip():
            return const.strip().upper()
    return ''


def _registry_path(schema: dict[str, Any], meta: dict[str, Any]) -> str:
    path = str(meta.get('path') or '').strip()
    if path:
        return path
    node = (schema.get('properties') or {}).get('path') if isinstance(schema.get('properties'), dict) else None
    if isinstance(node, dict):
        const = node.get('const')
        if isinstance(const, str) and const.strip():
            return const.strip()
    return ''


def coerce_call_arguments(
    arguments: dict[str, Any] | None,
    schema: dict[str, Any] | None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Turn flat or legacy arguments into the downstream proxy envelope.

    Client ``path`` and ``method`` are ignored. The registry values are sent instead.
    """
    if not isinstance(arguments, dict):
        arguments = {}
    if not isinstance(schema, dict) or not is_proxy_input_schema(schema):
        return dict(arguments)
    meta = meta if isinstance(meta, dict) else {}
    supplied = dict(arguments)
    supplied.pop('method', None)
    supplied.pop('path', None)
    buckets: dict[str, dict[str, Any]] = {section: {} for section in _SECTIONS}
    legacy = any(isinstance(supplied.get(section), dict) for section in _SECTIONS)
    if legacy:
        for section in _SECTIONS:
            raw = supplied.get(section)
            if isinstance(raw, dict):
                buckets[section] = dict(raw)
    else:
        fields = {section: set(_section(schema, section)[0]) for section in _SECTIONS}
        for key, value in supplied.items():
            if key in fields['path_params']:
                buckets['path_params'][key] = value
            elif key in fields['headers']:
                buckets['headers'][key] = value
            elif key in fields['query']:
                buckets['query'][key] = value
            elif key in fields['body']:
                buckets['body'][key] = value
            elif fields['body'] and not fields['query']:
                buckets['body'][key] = value
            else:
                buckets['query'][key] = value
    from apps.connector.mcp_tenant import is_hidden_agent_field, is_tenant_field
    from shellui_django.mcp.routing import McpToolArgumentError

    out: dict[str, Any] = {}
    method = _registry_method(schema, meta)
    path = _registry_path(schema, meta)
    if method:
        out['method'] = method
    if path:
        out['path'] = path
    header_names = meta.get('header_names') if isinstance(meta.get('header_names'), dict) else {}
    for section in _SECTIONS:
        if not buckets[section]:
            continue
        cleaned: dict[str, Any] = {}
        for key, value in buckets[section].items():
            if is_tenant_field(key):
                # Kept so the token binding can reject a company mismatch.
                cleaned[key] = value
                continue
            if is_hidden_agent_field(key):
                raise McpToolArgumentError(f'{key} is not an argument for this tool.')
            cleaned[key] = value
        if not cleaned:
            continue
        if section == 'headers':
            translated = {str(header_names.get(key) or key): value for key, value in cleaned.items()}
            out['headers'] = translated
        else:
            out[section] = cleaned
    return out


def http_headers_from_arguments(arguments: dict[str, Any] | None) -> dict[str, str]:
    """HTTP headers to add on the downstream tools/call. Auth headers are never copied."""
    if not isinstance(arguments, dict):
        return {}
    raw = arguments.get('headers')
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key).strip()
        if not name or name.lower() in {'authorization', 'cookie', 'proxy-authorization'}:
            continue
        if value is None:
            continue
        headers[name] = str(value)
    return headers


def _walk_trim(node: Any, *, description_limit: int, drop_descriptions: bool) -> None:
    """Shorten prose. Enum values and required lists stay intact."""
    if isinstance(node, dict):
        node.pop('example', None)
        node.pop('examples', None)
        if drop_descriptions:
            node.pop('description', None)
        elif description_limit >= 0 and 'description' in node:
            node['description'] = one_line(node.get('description'), limit=description_limit)
        for key, value in node.items():
            if key in {'enum', 'required'}:
                continue
            _walk_trim(value, description_limit=description_limit, drop_descriptions=drop_descriptions)
    elif isinstance(node, list):
        for item in node:
            _walk_trim(item, description_limit=description_limit, drop_descriptions=drop_descriptions)


def trim_input_schema(schema: dict[str, Any] | None, *, budget: int = DESCRIBE_SCHEMA_BUDGET) -> dict[str, Any]:
    """Keep type, enum, and required fields inside a character budget."""
    current = public_input_schema(schema)
    _walk_trim(current, description_limit=160, drop_descriptions=False)
    if _encoded_len(current) <= budget:
        return current
    _walk_trim(current, description_limit=0, drop_descriptions=True)
    props = current.get('properties')
    required_names = [str(key) for key in current.get('required') or []]
    while isinstance(props, dict) and props and _encoded_len(current) > budget:
        optional = [key for key in props if key not in required_names]
        if not optional:
            break
        props.pop(optional[-1])
    return current


def _encoded_len(value: object) -> int:
    return len(json.dumps(value, sort_keys=True, default=str))


def bound_describe_tools(tools: list[dict[str, Any]], *, budget: int = DESCRIBE_PAYLOAD_BUDGET) -> list[dict[str, Any]]:
    """Shrink describe rows until the compact JSON fits the budget."""
    rows = [dict(row) for row in tools]
    for row in rows:
        if isinstance(row.get('inputSchema'), dict):
            row['inputSchema'] = trim_input_schema(row['inputSchema'])
        if 'description' in row:
            row['description'] = one_line(row.get('description'))
    encoded = json.dumps(rows, sort_keys=True, default=str)
    if len(encoded) <= budget:
        return rows
    for row in rows:
        row.pop('description', None)
        schema = row.get('inputSchema')
        if isinstance(schema, dict):
            _walk_trim(schema, description_limit=0, drop_descriptions=True)
    return rows
