"""Normalize OpenAPI-derived JSON Schema for MCP tool inputs (strict client subsets).

Primary home: ``shellui_django.mcp.tool_input_schema`` in `django-commons` (release 0.4.1+).
This copy is the ai-service safety net for aggregated downstream tools until all services upgrade.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

_VALID_TYPES = frozenset({'string', 'integer', 'number', 'boolean', 'array', 'object', 'null'})


def _components(root: dict[str, Any]) -> dict[str, Any]:
    return (root.get('components') or {}).get('schemas') or {}


def resolve_schema(schema: dict[str, Any] | None, root: dict[str, Any], *, _seen: frozenset[str] | None = None) -> dict[str, Any]:
    if not schema or not isinstance(schema, dict):
        return {}
    ref = schema.get('$ref')
    if isinstance(ref, str) and ref.startswith('#/components/schemas/'):
        name = ref.rsplit('/', 1)[-1]
        seen = _seen or frozenset()
        if name in seen:
            return {'type': 'string', 'description': f'Unresolved circular $ref: {ref}'}
        target = _components(root).get(name)
        if isinstance(target, dict):
            return resolve_schema(deepcopy(target), root, _seen=seen | {name})
        return {'type': 'string', 'description': f'Unresolved $ref: {ref}'}
    return schema


def _primary_type(schema: dict[str, Any]) -> str | None:
    raw = schema.get('type')
    if isinstance(raw, str):
        return raw if raw in _VALID_TYPES else None
    if isinstance(raw, list):
        for candidate in raw:
            if candidate != 'null' and candidate in _VALID_TYPES:
                return str(candidate)
    return None


def openapi_schema_to_json_schema(schema: dict[str, Any] | None, root: dict[str, Any]) -> dict[str, Any]:
    """Convert an OpenAPI 3.0/3.1 schema fragment to a JSON Schema node for MCP clients."""
    resolved = resolve_schema(schema if isinstance(schema, dict) else None, root)
    if not resolved:
        return {'type': 'string', 'description': 'OpenAPI schema missing; treated as string.'}

    if 'anyOf' in resolved and isinstance(resolved['anyOf'], list):
        return _merge_any_of(resolved['anyOf'], root, description=resolved.get('description'))

    if 'oneOf' in resolved and isinstance(resolved['oneOf'], list):
        return _merge_any_of(resolved['oneOf'], root, description=resolved.get('description'))

    out: dict[str, Any] = {}
    if resolved.get('description'):
        out['description'] = str(resolved['description'])

    if 'const' in resolved:
        out['const'] = resolved['const']
        if 'type' not in out:
            out['type'] = _json_type_for_value(resolved['const'])

    if 'enum' in resolved and isinstance(resolved['enum'], list) and resolved['enum']:
        out['enum'] = list(resolved['enum'])
        if 'type' not in out:
            out['type'] = _json_type_for_value(resolved['enum'][0])

    typ = _primary_type(resolved)
    if typ:
        out['type'] = typ

    if typ == 'string' or out.get('type') == 'string':
        out['type'] = 'string'
        if resolved.get('format'):
            out['format'] = str(resolved['format'])
        for key in ('minLength', 'maxLength', 'pattern'):
            if key in resolved:
                out[key] = resolved[key]

    if typ == 'integer' or out.get('type') == 'integer':
        out['type'] = 'integer'
        for key in ('minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'):
            if key in resolved:
                out[key] = resolved[key]

    if typ == 'number' or out.get('type') == 'number':
        out['type'] = 'number'
        for key in ('minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'):
            if key in resolved:
                out[key] = resolved[key]

    if typ == 'boolean' or out.get('type') == 'boolean':
        out['type'] = 'boolean'

    if typ == 'array' or out.get('type') == 'array':
        out['type'] = 'array'
        items = resolved.get('items')
        out['items'] = openapi_schema_to_json_schema(items if isinstance(items, dict) else {'type': 'string'}, root)
        if 'minItems' in resolved:
            out['minItems'] = resolved['minItems']
        if 'maxItems' in resolved:
            out['maxItems'] = resolved['maxItems']

    props = resolved.get('properties')
    if isinstance(props, dict) or typ == 'object' or 'properties' in resolved:
        out['type'] = 'object'
        out['properties'] = {
            str(key): openapi_schema_to_json_schema(val if isinstance(val, dict) else {}, root)
            for key, val in (props if isinstance(props, dict) else {}).items()
        }
        out['additionalProperties'] = False
        req = resolved.get('required')
        if isinstance(req, list):
            required = [str(k) for k in req if str(k) in out['properties']]
            if required:
                out['required'] = required

    return ensure_validation_keywords(out)


def _json_type_for_value(value: Any) -> str:
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, int) and not isinstance(value, bool):
        return 'integer'
    if isinstance(value, float):
        return 'number'
    if isinstance(value, list):
        return 'array'
    if isinstance(value, dict):
        return 'object'
    return 'string'


def _merge_any_of(branches: list[Any], root: dict[str, Any], *, description: str | None = None) -> dict[str, Any]:
    normalized = [
        openapi_schema_to_json_schema(branch, root) for branch in branches if isinstance(branch, dict)
    ]
    normalized = [ensure_validation_keywords(n) for n in normalized if n]
    if not normalized:
        out = {'type': 'string'}
    elif all(n.get('type') == 'string' and 'enum' in n for n in normalized):
        enums: list[Any] = []
        for n in normalized:
            enums.extend(n.get('enum') or [])
        out = {'type': 'string', 'enum': enums}
    elif len({n.get('type') for n in normalized}) == 1:
        out = deepcopy(normalized[0])
    else:
        # Strict MCP clients reject property-level anyOf; prefer string with a hint.
        types = sorted({str(n.get('type') or 'unknown') for n in normalized})
        out = {
            'type': 'string',
            'description': (description or 'OpenAPI anyOf') + f' (union: {", ".join(types)})',
        }
    if description and 'description' not in out:
        out['description'] = str(description)
    return ensure_validation_keywords(out)


def ensure_validation_keywords(node: dict[str, Any] | None) -> dict[str, Any]:
    if not node or not isinstance(node, dict):
        return {'type': 'string'}
    if node.get('type') in _VALID_TYPES or 'enum' in node or 'const' in node:
        if node.get('type') == 'object':
            props = node.get('properties')
            if props is None:
                node = {**node, 'properties': {}, 'additionalProperties': bool(node.get('additionalProperties', False))}
            elif not isinstance(props, dict):
                node = {**node, 'properties': {}, 'additionalProperties': False}
            elif 'additionalProperties' not in node:
                node = {**node, 'additionalProperties': False}
            else:
                node = {
                    **node,
                    'properties': {k: ensure_validation_keywords(v if isinstance(v, dict) else {}) for k, v in props.items()},
                }
        if node.get('type') == 'array' and 'items' not in node:
            node = {**node, 'items': {'type': 'string'}}
        return node
    if 'properties' in node and isinstance(node['properties'], dict):
        return ensure_validation_keywords({**node, 'type': 'object', 'additionalProperties': node.get('additionalProperties', False)})
    if 'items' in node:
        return ensure_validation_keywords({**node, 'type': 'array'})
    return {'type': 'string', 'description': node.get('description') or 'Untyped OpenAPI schema; treated as string.'}


def _finalize_schema_node(node: dict[str, Any], *, field_name: str = '') -> dict[str, Any]:
    if '$ref' in node:
        return {
            'type': 'string',
            'description': str(node.get('description') or f'OpenAPI ref {node["$ref"]} (inlined as string).'),
        }
    if 'anyOf' in node or 'oneOf' in node:
        branches = node.get('anyOf') or node.get('oneOf') or []
        merged = _merge_any_of(
            branches if isinstance(branches, list) else [],
            {},
            description=node.get('description'),
        )
        node = {**node, **merged}
        node.pop('anyOf', None)
        node.pop('oneOf', None)
    raw_type = node.get('type')
    if isinstance(raw_type, list):
        non_null = [t for t in raw_type if t != 'null']
        node = {**node, 'type': non_null[0] if non_null else 'string'}
    node = ensure_validation_keywords(node)
    if not str(node.get('description') or '').strip() and field_name:
        node = {
            **node,
            'description': f'Value for `{field_name}` (Shellui MCP proxy field).',
        }
    if node.get('type') == 'object':
        props = node.get('properties')
        if isinstance(props, dict):
            node = {
                **node,
                'additionalProperties': False,
                'properties': {
                    k: _finalize_schema_node(v if isinstance(v, dict) else {}, field_name=str(k))
                    for k, v in props.items()
                },
            }
    if node.get('type') == 'array' and isinstance(node.get('items'), dict):
        node = {**node, 'items': _finalize_schema_node(node['items'], field_name=f'{field_name}[]')}
    return node


def finalize_tool_input_schema(schema: dict[str, Any]) -> dict[str, Any]:
    finalized = _finalize_schema_node(schema if isinstance(schema, dict) else {}, field_name='input')
    if finalized.get('type') != 'object':
        finalized = {
            'type': 'object',
            'properties': {'value': finalized},
            'required': ['value'],
            'additionalProperties': False,
        }
    finalized.setdefault('additionalProperties', False)
    return finalized


def normalize_tool_input_schema(schema: dict[str, Any], root: dict[str, Any] | None = None) -> dict[str, Any]:
    """Resolve refs and enforce validation keywords on a tool ``inputSchema``."""
    root = root or {}
    if not isinstance(schema, dict):
        return {'type': 'object', 'properties': {}, 'additionalProperties': False}
    if 'anyOf' in schema or 'oneOf' in schema:
        merged = _merge_any_of(schema.get('anyOf') or schema.get('oneOf') or [], root, description=schema.get('description'))
        schema = {**schema, **merged}
        schema.pop('anyOf', None)
        schema.pop('oneOf', None)
    normalized = openapi_schema_to_json_schema(schema, {'components': root.get('components') or schema.get('components') or {}})
    if normalized.get('type') != 'object':
        normalized = {
            'type': 'object',
            'properties': {'value': normalized},
            'required': ['value'],
            'additionalProperties': False,
        }
    normalized.setdefault('additionalProperties', False)
    return finalize_tool_input_schema(normalized)


def _walk_schema(node: Any, path: str) -> list[tuple[str, str]]:
    issues: list[tuple[str, str]] = []
    if not isinstance(node, dict):
        return issues
    if node == {}:
        issues.append((path or '$', 'bare empty schema'))
    if path == '' and ('anyOf' in node or 'oneOf' in node):
        issues.append((path or '$', 'top-level anyOf/oneOf'))
    if 'properties' in node and node.get('type') not in (None, 'object'):
        issues.append((path, 'properties without type object'))
    has_keyword = (
        node.get('type') in _VALID_TYPES
        or 'enum' in node
        or 'const' in node
        or '$ref' in node
    )
    if not has_keyword and node not in ({},):
        if not any(k in node for k in ('properties', 'items', 'anyOf', 'oneOf', 'allOf')):
            issues.append((path or '$', 'schema carries no validation keyword'))
    props = node.get('properties')
    if isinstance(props, dict):
        for key, val in props.items():
            child = f'{path}.properties.{key}' if path else f'properties.{key}'
            issues.extend(_walk_schema(val, child))
    if isinstance(node.get('items'), dict):
        child = f'{path}.items' if path else 'items'
        issues.extend(_walk_schema(node['items'], child))
    for key in ('anyOf', 'oneOf', 'allOf'):
        branches = node.get(key)
        if isinstance(branches, list):
            for idx, branch in enumerate(branches):
                if isinstance(branch, dict):
                    issues.extend(_walk_schema(branch, f'{path}.{key}[{idx}]' if path else f'{key}[{idx}]'))
    return issues


def strict_client_schema_issues(schema: dict[str, Any]) -> list[tuple[str, str]]:
    """Return paths that violate Shellui MCP / OpenAI / Gemini function-schema subsets."""
    return _walk_schema(schema, '')


def audit_tool_input_schemas(tools: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    """``(tool_name, json_path, reason)`` for every schema violation."""
    rows: list[tuple[str, str, str]] = []
    for tool in tools:
        name = str(tool.get('name') or '<unnamed>')
        input_schema = tool.get('inputSchema') or {}
        for path, reason in strict_client_schema_issues(input_schema if isinstance(input_schema, dict) else {}):
            rows.append((name, path, reason))
    return rows


def normalize_mcp_tool(tool: dict[str, Any], root: dict[str, Any] | None = None) -> dict[str, Any]:
    from apps.connector.mcp_tool_presentation import sanitize_shellui_copy

    out = deepcopy(tool)
    schema = out.get('inputSchema')
    if isinstance(schema, dict):
        out['inputSchema'] = normalize_tool_input_schema(schema, root)
    desc = sanitize_shellui_copy(str(out.get('description') or '').strip())
    name = str(out.get('name') or 'tool')
    if len(desc) < 24:
        op = (out.get('_meta') or {}).get('operationId') or name
        desc = desc or f'Shellui MCP tool {name} ({op}).'
    out['description'] = desc
    if not str(out.get('title') or '').strip():
        from apps.connector.mcp_tool_presentation import human_title_from_tool_name

        out['title'] = human_title_from_tool_name(name)
    if not isinstance(out.get('annotations'), dict):
        meta = out.get('_meta') or {}
        read_only = bool(meta.get('read_only'))
        destructive = bool(meta.get('destructive'))
        out['annotations'] = {
            'readOnlyHint': read_only,
            'destructiveHint': destructive and not read_only,
            'idempotentHint': read_only,
            'openWorldHint': False,
        }
    return out
