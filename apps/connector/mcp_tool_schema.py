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


def _component_ref_name(schema: dict[str, Any]) -> str | None:
    ref = schema.get('$ref')
    if isinstance(ref, str) and ref.startswith('#/components/schemas/'):
        return ref.rsplit('/', 1)[-1]
    return None


def resolve_schema(schema: dict[str, Any] | None, root: dict[str, Any], *, _seen: frozenset[str] | None = None) -> dict[str, Any]:
    if not schema or not isinstance(schema, dict):
        return {}
    ref = schema.get('$ref')
    if isinstance(ref, str) and ref.startswith('#/components/schemas/'):
        name = ref.rsplit('/', 1)[-1]
        seen = _seen or frozenset()
        if name in seen:
            if name == 'EmailDocumentNode':
                from apps.connector.mcp_json_contracts import email_document_node

                return email_document_node()
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


def _is_untyped_json(schema: dict[str, Any]) -> bool:
    """True for spectacular ``JSONField`` fragments (``{}`` or a description only)."""
    if not schema:
        return True
    if any(key in schema for key in ('type', 'properties', 'enum', 'const', 'items', 'anyOf', 'oneOf', 'allOf', '$ref')):
        return False
    return set(schema.keys()) <= {'description', 'title', 'example', 'nullable', 'readOnly', 'writeOnly', 'deprecated'}


def _overlay_description(node: dict[str, Any], description: str | None) -> dict[str, Any]:
    text = str(description or '').strip()
    if not text:
        return node
    current = str(node.get('description') or '').strip()
    if not current:
        return {**node, 'description': text}
    if text in current:
        return node
    return {**node, 'description': f'{text} {current}'.strip()}


def openapi_schema_to_json_schema(
    schema: dict[str, Any] | None,
    root: dict[str, Any],
    *,
    _seen: set[str] | None = None,
) -> dict[str, Any]:
    """Convert an OpenAPI 3.0/3.1 schema fragment to a JSON Schema node for MCP clients."""
    if not isinstance(schema, dict):
        return {'type': 'string', 'description': 'OpenAPI schema missing; treated as string.'}
    seen = _seen if _seen is not None else set()
    ref_name = _component_ref_name(schema)
    if ref_name:
        if ref_name in seen:
            if ref_name == 'EmailDocumentNode':
                from apps.connector.mcp_json_contracts import email_document_node

                cycled = ensure_validation_keywords(email_document_node())
            else:
                ref = schema.get('$ref')
                cycled = {'type': 'string', 'description': f'Unresolved circular $ref: {ref}'}
            return _overlay_description(cycled, schema.get('description') if isinstance(schema.get('description'), str) else None)
        target = _components(root).get(ref_name)
        if not isinstance(target, dict):
            ref = schema.get('$ref')
            return {'type': 'string', 'description': f'Unresolved $ref: {ref}'}
        seen.add(ref_name)
        try:
            inlined = openapi_schema_to_json_schema(target, root, _seen=seen)
        finally:
            seen.discard(ref_name)
        return _overlay_description(inlined, schema.get('description') if isinstance(schema.get('description'), str) else None)

    resolved = schema
    # ``{}`` is a valid spectacular JSONField fragment — do not treat it as missing.

    if 'allOf' in resolved and isinstance(resolved['allOf'], list):
        return _merge_all_of(resolved['allOf'], root, description=resolved.get('description'), _seen=seen)

    if 'anyOf' in resolved and isinstance(resolved['anyOf'], list):
        return _merge_any_of(resolved['anyOf'], root, description=resolved.get('description'), _seen=seen)

    if 'oneOf' in resolved and isinstance(resolved['oneOf'], list):
        return _merge_any_of(resolved['oneOf'], root, description=resolved.get('description'), _seen=seen)

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
        out['items'] = openapi_schema_to_json_schema(
            items if isinstance(items, dict) else {'type': 'string'},
            root,
            _seen=seen,
        )
        if 'minItems' in resolved:
            out['minItems'] = resolved['minItems']
        if 'maxItems' in resolved:
            out['maxItems'] = resolved['maxItems']

    props = resolved.get('properties')
    if isinstance(props, dict) or typ == 'object' or 'properties' in resolved:
        out['type'] = 'object'
        prop_map = props if isinstance(props, dict) else {}
        sibling_names = {str(key) for key in prop_map}
        out['properties'] = {
            str(key): _convert_property(str(key), val if isinstance(val, dict) else {}, root, sibling_names, seen)
            for key, val in prop_map.items()
        }
        # Keep an explicit free-form object (additionalProperties: true). A schema
        # for the extra values (DictField child, map of blocks) is preserved.
        out['additionalProperties'] = _additional_keyword(resolved.get('additionalProperties'), root, seen)
        req = resolved.get('required')
        if isinstance(req, list):
            required = [str(k) for k in req if str(k) in out['properties']]
            if required:
                out['required'] = required
        return _with_schema_default(out, resolved)

    # drf-spectacular JSONField often emits ``{}`` or description-only nodes. Treat those
    # as free-form objects so MCP clients can submit nested draft payloads (e.g. document).
    if not typ and 'const' not in resolved and 'enum' not in resolved and 'items' not in resolved:
        out['type'] = 'object'
        out['additionalProperties'] = True
        if not out.get('description'):
            out['description'] = 'JSON value (OpenAPI schema had no type).'
        return _with_schema_default(out, resolved)

    return _with_schema_default(out, resolved)


def _with_schema_default(out: dict[str, Any], resolved: dict[str, Any]) -> dict[str, Any]:
    if 'default' in resolved and 'default' not in out:
        out['default'] = resolved['default']
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


def _is_shellui_open_object(schema: dict[str, Any]) -> bool:
    """shellui turns OpenAPI ``additionalProperties: {}`` into an open object with no properties."""
    if schema.get('type') != 'object' or schema.get('additionalProperties') is not True:
        return False
    props = schema.get('properties')
    if isinstance(props, dict) and props:
        return False
    return not any(key in schema for key in ('enum', 'const', 'items', 'anyOf', 'oneOf', 'allOf', '$ref'))


def _convert_property(
    key: str,
    raw: dict[str, Any],
    root: dict[str, Any],
    sibling_names: set[str],
    seen: set[str],
) -> dict[str, Any]:
    """Type bare JSONField properties whose contract is known; otherwise convert normally."""
    if not _component_ref_name(raw) and 'allOf' not in raw and 'anyOf' not in raw and 'oneOf' not in raw:
        peeked = resolve_schema(raw, root)
        if _is_untyped_json(peeked) or _is_shellui_open_object(peeked):
            from apps.connector.mcp_json_contracts import contract_for_untyped_field

            contract = contract_for_untyped_field(key, str(peeked.get('description') or ''), sibling_names)
            if contract is not None:
                return ensure_validation_keywords(contract)
        if _is_shellui_open_object(peeked):
            # Audited converter closes an empty ``additionalProperties: {}`` schema.
            closed = {k: v for k, v in peeked.items() if k != 'additionalProperties'}
            closed['type'] = 'object'
            closed['additionalProperties'] = {}
            return openapi_schema_to_json_schema(closed, root, _seen=seen)
    return openapi_schema_to_json_schema(raw, root, _seen=seen)


def _additional_keyword(value: Any, root: dict[str, Any], seen: set[str]) -> bool | dict[str, Any]:
    """Preserve ``true`` and typed value schemas. An empty ``{}`` stays closed."""
    if value is True:
        return True
    if not isinstance(value, dict):
        return False
    if not any(key in value for key in ('type', '$ref', 'allOf', 'anyOf', 'oneOf', 'properties', 'items', 'enum', 'const')):
        return False
    return openapi_schema_to_json_schema(value, root, _seen=seen)


def _preserve_additional(value: Any) -> bool | dict[str, Any]:
    if value is True:
        return True
    if isinstance(value, dict) and (
        value.get('type') in _VALID_TYPES or value.get('properties') or value.get('items') or value.get('enum') or value.get('const')
    ):
        return value
    return False


def _merge_all_of(
    branches: list[Any],
    root: dict[str, Any],
    *,
    description: str | None = None,
    _seen: set[str] | None = None,
) -> dict[str, Any]:
    """Inline ``allOf`` (spectacular wraps a described ``$ref`` this way) into one object."""
    seen = _seen if _seen is not None else set()
    parts = [
        openapi_schema_to_json_schema(branch, root, _seen=seen)
        for branch in branches
        if isinstance(branch, dict)
    ]
    objects = [part for part in parts if part.get('type') == 'object' or isinstance(part.get('properties'), dict)]
    if not objects:
        merged = parts[0] if parts else {'type': 'object', 'properties': {}, 'additionalProperties': False}
        return ensure_validation_keywords(_overlay_description(merged, description if isinstance(description, str) else None))
    properties: dict[str, Any] = {}
    required: list[str] = []
    additional: bool | dict[str, Any] = False
    merged_description = ''
    for obj in objects:
        obj_props = obj.get('properties')
        if isinstance(obj_props, dict):
            properties.update(obj_props)
        for key in obj.get('required') or []:
            if key not in required and key in properties:
                required.append(str(key))
        obj_additional = obj.get('additionalProperties')
        if obj_additional is True:
            additional = True
        elif isinstance(obj_additional, dict) and additional is not True:
            additional = obj_additional
        if obj.get('description') and not merged_description:
            merged_description = str(obj['description'])
    merged = {
        'type': 'object',
        'description': merged_description or 'Combined schema.',
        'properties': properties,
        'additionalProperties': additional,
    }
    if required:
        merged['required'] = required
    return ensure_validation_keywords(_overlay_description(merged, description if isinstance(description, str) else None))


def _merge_any_of(
    branches: list[Any],
    root: dict[str, Any],
    *,
    description: str | None = None,
    _seen: set[str] | None = None,
) -> dict[str, Any]:
    seen = _seen if _seen is not None else set()
    normalized = [
        openapi_schema_to_json_schema(branch, root, _seen=seen) for branch in branches if isinstance(branch, dict)
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
            additional = _preserve_additional(node.get('additionalProperties'))
            if isinstance(additional, dict):
                additional = ensure_validation_keywords(additional)
            if not isinstance(props, dict):
                node = {**node, 'properties': {}, 'additionalProperties': additional}
            else:
                node = {
                    **node,
                    'additionalProperties': additional,
                    'properties': {k: ensure_validation_keywords(v if isinstance(v, dict) else {}) for k, v in props.items()},
                }
        if node.get('type') == 'array' and 'items' not in node:
            node = {**node, 'items': {'type': 'string'}}
        return node
    if 'properties' in node and isinstance(node['properties'], dict):
        return ensure_validation_keywords({**node, 'type': 'object', 'additionalProperties': _preserve_additional(node.get('additionalProperties'))})
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
        # Preserve explicit free-form objects and typed additionalProperties schemas.
        additional = _preserve_additional(node.get('additionalProperties'))
        if isinstance(additional, dict):
            additional = _finalize_schema_node(additional, field_name=f'{field_name}.*' if field_name else '')
        if isinstance(props, dict):
            node = {
                **node,
                'additionalProperties': additional,
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


def _operation_from_input_schema(schema: dict[str, Any] | None) -> tuple[str | None, str | None]:
    """Recover OpenAPI path/method from legacy proxy ``inputSchema`` (clients strip ``_meta``)."""
    if not isinstance(schema, dict):
        return None, None
    props = schema.get('properties')
    if not isinstance(props, dict):
        return None, None
    path = None
    method = None
    path_node = props.get('path')
    if isinstance(path_node, dict):
        const = path_node.get('const')
        if isinstance(const, str) and const.strip():
            path = const.strip()
        elif isinstance(path_node.get('enum'), list) and path_node['enum']:
            first = path_node['enum'][0]
            if isinstance(first, str) and first.strip():
                path = first.strip()
    method_node = props.get('method')
    if isinstance(method_node, dict):
        const = method_node.get('const')
        if isinstance(const, str) and const.strip():
            method = const.strip().upper()
        elif isinstance(method_node.get('enum'), list) and method_node['enum']:
            first = method_node['enum'][0]
            if isinstance(first, str) and first.strip():
                method = first.strip().upper()
    return path, method


# Downstream tools/list omits `_meta`, so x-mcp flags that differ from the HTTP
# method are not on the wire. These operation ids are the POST exceptions on the
# identity, storage, hosting, and email OpenAPI registries: read-only searches
# and previews, and destructive revokes / empty / rollback. The release contract
# test fails if a fixture gains another exception that is not listed here.
# (service, operation id). The same operation id can be destructive in one
# service and a normal write in another, so the pair is the key.
READ_ONLY_POST_OPERATION_IDS = frozenset(
    {
        ('email', 'api_v1_broadcasts_preview'),
        ('email', 'api_v1_templates_render_preview'),
        ('storage', 'storage_v1_object_list_create'),
    }
)
DESTRUCTIVE_POST_OPERATION_IDS = frozenset(
    {
        ('hosting', 'api_v1_actions_rules_rotate_secret'),
        ('hosting', 'hosting_v1_apps_deployments_finalize_create'),
        ('hosting', 'hosting_v1_apps_deployments_rollback_create'),
        ('hosting', 'hosting_v1_apps_domains_create'),
        ('hosting', 'hosting_v1_apps_domains_refresh_create'),
        ('hosting', 'hosting_v1_apps_environment_create'),
        ('hosting', 'hosting_v1_apps_environment_update'),
        ('hosting', 'hosting_v1_deploy_tokens_revoke_create'),
        ('identity', 'identity_revoke_personal_access_tokens'),
        ('identity', 'identity_revoke_scim_tokens'),
        ('storage', 'storage_v1_bucket_empty_create'),
    }
)
# Gateway export name -> operation id, so a tools/list that already uses the
# published name still picks up the exception above.
_EXPORT_OPERATION_IDS = {
    'email_broadcasts_preview': 'api_v1_broadcasts_preview',
    'email_render_preview_templates': 'api_v1_templates_render_preview',
    'hosting_create_apps_deployments_finalize': 'hosting_v1_apps_deployments_finalize_create',
    'hosting_create_apps_deployments_rollback': 'hosting_v1_apps_deployments_rollback_create',
    'hosting_create_apps_domains': 'hosting_v1_apps_domains_create',
    'hosting_create_apps_domains_refresh': 'hosting_v1_apps_domains_refresh_create',
    'hosting_create_apps_environment': 'hosting_v1_apps_environment_create',
    'hosting_replace_apps_environment': 'hosting_v1_apps_environment_update',
    'hosting_revoke_deploy_token': 'hosting_v1_deploy_tokens_revoke_create',
    'hosting_rotate_rule_secret': 'api_v1_actions_rules_rotate_secret',
    'storage_create_object_list': 'storage_v1_object_list_create',
    'storage_empty_bucket': 'storage_v1_bucket_empty_create',
}


def _service_from_tool_name(tool_name: str) -> str:
    name = str(tool_name or '')
    for service_id in ('identity', 'storage', 'hosting', 'email', 'saas'):
        if name == service_id or name.startswith(f'{service_id}_'):
            return service_id
    return ''


def apply_operation_access(meta: dict[str, Any], *, tool_name: str, service_id: str = '') -> dict[str, Any]:
    """Apply the per-service read-only and destructive POST exceptions."""
    out = dict(meta)
    keys = {
        str(out.get('operationId') or ''),
        str(tool_name or ''),
        str(out.get('legacy_tool_name') or ''),
    }
    keys.discard('')
    keys.update(_EXPORT_OPERATION_IDS[key] for key in list(keys) if key in _EXPORT_OPERATION_IDS)
    service = str(service_id or _service_from_tool_name(tool_name) or '')
    if not service:
        owners = {
            pair_service
            for pair_service, key in READ_ONLY_POST_OPERATION_IDS | DESTRUCTIVE_POST_OPERATION_IDS
            if key in keys
        }
        if len(owners) == 1:
            service = next(iter(owners))
    if not service:
        return out
    if any((service, key) in READ_ONLY_POST_OPERATION_IDS for key in keys):
        out['read_only'] = True
        out['destructive'] = False
    elif any((service, key) in DESTRUCTIVE_POST_OPERATION_IDS for key in keys):
        out['destructive'] = True
        out['read_only'] = False
    elif str(out.get('method') or '').upper() != 'DELETE':
        # The same operation id can be destructive for one service only.
        # A guess made before the service was known must not stick.
        foreign = {key for svc, key in DESTRUCTIVE_POST_OPERATION_IDS if svc != service}
        if keys & foreign:
            out['destructive'] = False
    return out


def recover_registry_access(
    meta: dict[str, Any],
    *,
    tool_name: str,
    explicit_read_only: bool = False,
    explicit_destructive: bool = False,
    service_id: str = '',
) -> dict[str, Any]:
    """Fill operation id and access flags stripped from a downstream tools/list row."""
    from apps.connector.mcp_tool_naming import (
        legacy_operation_id_from_tool_name,
        operation_id_for_upstream_tool_name,
    )

    out = dict(meta)
    x_mcp = out.get('x-mcp') if isinstance(out.get('x-mcp'), dict) else {}
    current = str(out.get('operationId') or '').strip()
    if not current:
        recovered = operation_id_for_upstream_tool_name(tool_name)
        if recovered:
            out['operationId'] = recovered
    elif legacy_operation_id_from_tool_name(current) is None:
        # Older catalogs used the registry slug. Keep a published operation id
        # that is already in the exception sets above.
        mapped = operation_id_for_upstream_tool_name(current) or operation_id_for_upstream_tool_name(tool_name)
        if mapped:
            out['operationId'] = mapped
    # Upstream ``x-mcp`` is the access source when the service sent it. tools/list
    # usually drops ``_meta``, and the operation-id sets remain the fallback.
    if not explicit_destructive and 'destructive' in x_mcp:
        out['destructive'] = bool(x_mcp.get('destructive'))
        explicit_destructive = True
        if out['destructive']:
            out['read_only'] = False
            explicit_read_only = True
    if not explicit_read_only and 'read_only' in x_mcp:
        out['read_only'] = bool(x_mcp.get('read_only'))
        explicit_read_only = True
    if out.get('destructive') and not explicit_read_only:
        out['read_only'] = False
    oid = str(out.get('operationId') or '')
    method = str(out.get('method') or '').upper()
    if not explicit_read_only and oid in READ_ONLY_POST_OPERATION_IDS:
        out['read_only'] = True
        out['destructive'] = False
    elif not explicit_destructive and oid in DESTRUCTIVE_POST_OPERATION_IDS:
        out['destructive'] = True
        out['read_only'] = False
    elif method == 'DELETE' and not explicit_destructive:
        out['destructive'] = True
    elif method in {'GET', 'HEAD', 'OPTIONS'} and not explicit_read_only:
        out['read_only'] = True
    return apply_operation_access(out, tool_name=tool_name, service_id=service_id)


def _ensure_operation_meta(meta: dict[str, Any], schema: dict[str, Any] | None) -> dict[str, Any]:
    """Fill missing ``_meta.path`` / ``_meta.method`` from the tool's proxy input schema."""
    out = dict(meta) if isinstance(meta, dict) else {}
    path, method = _operation_from_input_schema(schema)
    if not str(out.get('path') or '').strip() and path:
        out['path'] = path
    if not str(out.get('method') or '').strip() and method:
        out['method'] = method
    method_u = str(out.get('method') or '').strip().upper()
    if method_u:
        out['method'] = method_u
        if 'read_only' not in out:
            out['read_only'] = method_u in {'GET', 'HEAD', 'OPTIONS'}
        if 'destructive' not in out:
            out['destructive'] = method_u == 'DELETE'
    return out


def normalize_mcp_tool(tool: dict[str, Any], root: dict[str, Any] | None = None) -> dict[str, Any]:
    from apps.connector.mcp_tool_presentation import sanitize_shellui_copy
    from apps.connector.mcp_tenant import apply_tenant_meta_from_binding, strip_tenant_fields_from_input_schema

    out = deepcopy(tool)
    schema = out.get('inputSchema')
    raw_schema = deepcopy(schema) if isinstance(schema, dict) else None
    incoming_meta = out.get('_meta') if isinstance(out.get('_meta'), dict) else {}
    explicit_read_only = 'read_only' in incoming_meta
    explicit_destructive = 'destructive' in incoming_meta
    meta = dict(incoming_meta)
    meta = _ensure_operation_meta(meta, raw_schema)
    if isinstance(schema, dict):
        tenant_binding = strip_tenant_fields_from_input_schema(schema)
        out['inputSchema'] = normalize_tool_input_schema(schema, root)
        # Re-read path/method after tenant strip; keep any recovered operation meta.
        meta = _ensure_operation_meta(
            meta,
            out.get('inputSchema') if isinstance(out.get('inputSchema'), dict) else raw_schema,
        )
        if tenant_binding or meta:
            out['_meta'] = apply_tenant_meta_from_binding(meta, tenant_binding)
    elif meta:
        out['_meta'] = meta
    name = str(out.get('name') or 'tool')
    meta = out.get('_meta') if isinstance(out.get('_meta'), dict) else {}
    meta = recover_registry_access(
        meta,
        tool_name=name,
        explicit_read_only=explicit_read_only,
        explicit_destructive=explicit_destructive,
    )
    out['_meta'] = meta
    from apps.connector.mcp_tool_naming import (
        legacy_operation_id_from_tool_name,
        tool_name_has_service_prefix,
    )
    from apps.connector.mcp_tool_presentation import human_title_from_tool_name, strip_presentation_noise

    # Leave titles empty for operation-id slugs and for names that already carry a
    # service prefix, so the gateway titles the export (``Identity: Create Groups``).
    if str(out.get('title') or '').strip():
        out['title'] = strip_presentation_noise(str(out.get('title') or ''))
    elif legacy_operation_id_from_tool_name(name) is None and not tool_name_has_service_prefix(name):
        out['title'] = human_title_from_tool_name(name)
    desc = strip_presentation_noise(str(out.get('description') or '').strip())
    if len(desc) < 24:
        title = str(out.get('title') or '').strip() or 'Shellui tool'
        if desc:
            if desc[-1] not in '.!?':
                desc += '.'
            desc = f'{desc} Runs one company-scoped Shellui API operation.'
        else:
            desc = f'{title}. Runs one company-scoped Shellui API operation.'
        desc = sanitize_shellui_copy(strip_presentation_noise(desc))
    out['description'] = desc
    ann = out.get('annotations')
    meta = out.get('_meta') if isinstance(out.get('_meta'), dict) else {}
    method = str(meta.get('method') or '').strip().upper()
    hints_complete = isinstance(ann, dict) and all(
        key in ann for key in ('readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint')
    )
    # Downstream catalogs often ship placeholder all-false annotations; rebuild when we know the method.
    placeholder_ann = hints_complete and not any(
        bool(ann.get(k)) for k in ('readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint')
    )
    if not hints_complete or (placeholder_ann and method):
        from apps.connector.mcp_tool_presentation import tool_annotations

        access = {
            'read_only': bool(meta.get('read_only')) if 'read_only' in meta else method in {'GET', 'HEAD', 'OPTIONS'},
            'destructive': bool(meta.get('destructive')) if 'destructive' in meta else method == 'DELETE',
        }
        if method:
            operation = {'operationId': meta.get('operationId') or name}
            out['annotations'] = tool_annotations(operation, method=method, access=access)
        else:
            core = name.split('_', 1)[1] if '_' in name else name
            read_only = core.startswith(('list_', 'get_')) or core.endswith(('_list', '_retrieve', '_get'))
            # Names like update_ and replace_ are ordinary writes. Only a delete is
            # destructive when the registry did not say so.
            destructive = core.startswith(('delete_', 'destroy_')) or core.endswith(('_destroy', '_delete'))
            out['annotations'] = {
                'readOnlyHint': read_only,
                'destructiveHint': destructive and not read_only,
                'idempotentHint': read_only or core.startswith(('replace_', 'delete_')) or core.endswith(('_destroy', '_delete', '_replace')),
                'openWorldHint': 'send' in core,
            }
    return out
