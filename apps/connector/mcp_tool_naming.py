"""Stable MCP tool names from OpenAPI operations (mirrors shellui-django 0.4.2 ``tool_naming``)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

MCP_TOOL_TAG = 'mcp-tools'
TOOL_NAME_MAX_LEN = 64
TOOL_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')

_HTTP_METHODS = frozenset({'get', 'post', 'put', 'patch', 'delete'})

_ACTION_SUFFIXES: tuple[tuple[str, str], ...] = (
    ('partial_update', 'update'),
    ('delete_many', 'delete_many'),
    ('authenticated_retrieve', 'get'),
    ('info_authenticated_retrieve', 'get_info'),
    ('info_public_retrieve', 'get_info'),
    ('public_retrieve', 'get'),
    ('render_preview', 'render_preview'),
    ('sign_path_create', 'sign_path'),
    ('empty_create', 'empty'),
    ('move_create', 'move'),
    ('copy_create', 'copy'),
    ('sign_create', 'sign'),
    ('link_destroy', 'delete_link'),
    ('send_test', 'send_test'),
    ('rotate_secret', 'rotate_secret'),
    ('test_send', 'test_send'),
    ('requeue', 'requeue'),
    ('publish', 'publish'),
    ('cancel', 'cancel'),
    ('retrieve', 'get'),
    ('destroy', 'delete'),
    ('create', 'create'),
    ('list', 'list'),
    ('update', 'update'),
)

_RESOURCE_ALIASES = {
    'mcp_services': 'services',
    'service_clients': 'clients',
}


def legacy_slug_tool_name(method: str, path: str, operation_id: str | None) -> str:
    if operation_id:
        base = re.sub(r'[^a-zA-Z0-9_]+', '_', operation_id).strip('_').lower()
        if base:
            return base[:120]
    cleaned = re.sub(r'[^a-zA-Z0-9_]+', '_', f'{method}_{path}').strip('_').lower()
    return cleaned[:120]


def _sanitize_token(raw: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_]+', '_', raw).strip('_').lower()


def _strip_version_and_service_prefix(tokens: list[str]) -> list[str]:
    out = list(tokens)
    changed = True
    while changed and out:
        changed = False
        if out[0] in {'api', 'actions', 'service'}:
            out.pop(0)
            changed = True
            continue
        if re.fullmatch(r'v\d+', out[0] or ''):
            out.pop(0)
            changed = True
            continue
        if len(out) >= 2 and out[0] in {'storage', 'hosting', 'email', 'identity', 'saas', 'ai'} and re.fullmatch(
            r'v\d+', out[1] or ''
        ):
            out = out[2:]
            changed = True
    return out


def _resource_label(resource: str, verb: str) -> str:
    if not resource:
        return verb
    resource = _RESOURCE_ALIASES.get(resource, resource)
    if verb in {'list', 'get', 'create', 'delete', 'update'}:
        if verb == 'list':
            return f'list_{resource}'
        if verb == 'get':
            return f'get_{resource}'
        if verb == 'create':
            return f'create_{resource}'
        if verb == 'delete':
            return f'delete_{resource}'
        return f'update_{resource}'
    return f'{verb}_{resource}' if not resource.startswith(verb) else f'{verb}_{resource}'


def _base_name_from_stripped(stripped: str, *, method: str) -> str:
    if not stripped:
        return _sanitize_token(method)
    for suffix, verb in _ACTION_SUFFIXES:
        if stripped == suffix:
            return verb
        needle = f'_{suffix}'
        if stripped.endswith(needle):
            resource = stripped[: -len(needle)]
            return _resource_label(resource, verb)
    return stripped


def resolve_mcp_tool_name(operation: dict[str, Any], method: str, path: str) -> str:
    x_mcp = operation.get('x-mcp') if isinstance(operation.get('x-mcp'), dict) else {}
    explicit = str(x_mcp.get('tool_name') or x_mcp.get('name') or '').strip()
    if explicit:
        return clamp_tool_name(_sanitize_token(explicit))

    op_id = operation.get('operationId')
    if op_id:
        tokens = _strip_version_and_service_prefix(_sanitize_token(str(op_id)).split('_'))
        stripped = '_'.join(tokens)
        return clamp_tool_name(_base_name_from_stripped(stripped, method=method))

    fallback = _sanitize_token(f'{method}_{path}')
    fallback = re.sub(r'api_v\d+_', '', fallback)
    fallback = re.sub(r'_+', '_', fallback).strip('_')
    return clamp_tool_name(_base_name_from_stripped(fallback, method=method))


def clamp_tool_name(name: str) -> str:
    name = name.strip('_')
    if len(name) <= TOOL_NAME_MAX_LEN and TOOL_NAME_RE.match(name):
        return name
    trimmed = name[:TOOL_NAME_MAX_LEN].rstrip('_')
    if TOOL_NAME_RE.match(trimmed):
        return trimmed
    return re.sub(r'[^a-zA-Z0-9_-]+', '_', trimmed)[:TOOL_NAME_MAX_LEN].strip('_')


def ensure_unique_tool_names(proposed: list[str]) -> list[str]:
    taken: set[str] = set()
    out: list[str] = []
    for name in proposed:
        candidate = name
        n = 2
        while candidate in taken or not candidate:
            suffix = f'_{n}'
            base = name[: max(1, TOOL_NAME_MAX_LEN - len(suffix))].rstrip('_')
            candidate = clamp_tool_name(f'{base}{suffix}')
            n += 1
        taken.add(candidate)
        out.append(candidate)
    return out


def canonical_downstream_tool_name(name: str, *, service_id: str | None = None) -> str:
    """Map legacy ``api_v1_*`` downstream names to ``verb_noun`` before gateway export."""
    tokens = _sanitize_token(name).split('_')
    if service_id:
        sid = _sanitize_token(service_id)
        if tokens and tokens[0] == sid:
            tokens = tokens[1:]
    joined = '_'.join(tokens)
    if 'api_v' in joined or joined.startswith('api_'):
        stripped_tokens = _strip_version_and_service_prefix(tokens)
        stripped = '_'.join(stripped_tokens)
        return clamp_tool_name(_base_name_from_stripped(stripped, method='get'))
    return clamp_tool_name(joined or name)


def gateway_export_name(service_id: str, downstream_name: str, *, taken: set[str] | None = None) -> str:
    service_id = _sanitize_token(service_id)
    downstream_name = clamp_tool_name(downstream_name)
    export_name = clamp_tool_name(f'{service_id}_{downstream_name}')
    if taken is None:
        return export_name
    candidate = export_name
    n = 2
    while candidate in taken:
        suffix = f'_{n}'
        base = export_name[: max(1, TOOL_NAME_MAX_LEN - len(suffix))].rstrip('_')
        candidate = clamp_tool_name(f'{base}{suffix}')
        n += 1
    taken.add(candidate)
    return candidate


def path_api_version(path: str) -> int:
    match = re.search(r'/api/v(\d+)/', str(path))
    return int(match.group(1)) if match else 0


def versionless_path(path: str) -> str:
    return re.sub(r'/api/v\d+/', '/api/v/', str(path))


def iter_mcp_operations(schema: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    paths = schema.get('paths') or {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            tags = operation.get('tags') or []
            if MCP_TOOL_TAG not in tags:
                continue
            yield str(path), method.lower(), operation


def select_newest_api_version_operations(
    schema: dict[str, Any],
) -> list[tuple[str, str, dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[tuple[int, str, str, dict[str, Any]]]] = {}
    for path, method, operation in iter_mcp_operations(schema):
        key = (method.upper(), versionless_path(path))
        grouped.setdefault(key, []).append((path_api_version(path), path, method, operation))
    selected: list[tuple[str, str, dict[str, Any]]] = []
    for items in grouped.values():
        _version, path, method, operation = max(items, key=lambda row: (row[0], row[1]))
        selected.append((path, method, operation))
    selected.sort(key=lambda row: (resolve_mcp_tool_name(row[2], row[1], row[0]), row[0], row[1]))
    return selected


def validate_tool_name(name: str) -> list[str]:
    issues: list[str] = []
    if not name:
        issues.append('empty')
    if len(name) > TOOL_NAME_MAX_LEN:
        issues.append('too_long')
    if not TOOL_NAME_RE.match(name):
        issues.append('invalid_chars')
    return issues
