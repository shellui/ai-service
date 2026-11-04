"""MCP tool presentation (title, description, annotations, outputSchema) from OpenAPI."""

from __future__ import annotations

import re
from typing import Any

from shellui_django.mcp.openapi_mcp import tool_access_flags

from apps.connector.mcp_tool_schema import openapi_schema_to_json_schema

_SENTENCE_END = re.compile(r'(?<=[.!?])\s+')
_EM_EN_DASH = re.compile(r'[\u2013\u2014\u2012]')
_SHELLUI_WORD = re.compile(r'\bshellui\b', re.I)


def sanitize_shellui_copy(text: str) -> str:
    """Shellui writing rules: no em/en dashes; brand is ``Shellui``."""
    if not text:
        return ''
    out = _EM_EN_DASH.sub(', ', str(text))
    out = re.sub(r'\s+', ' ', out).strip()
    out = _SHELLUI_WORD.sub('Shellui', out)
    out = re.sub(r',\s*,', ', ', out)
    out = re.sub(r'\s+,', ',', out)
    return out


def _first_sentences(text: str, *, max_sentences: int = 2) -> str:
    cleaned = sanitize_shellui_copy(text)
    if not cleaned:
        return ''
    parts = _SENTENCE_END.split(cleaned)
    if len(parts) <= max_sentences:
        return cleaned
    return ' '.join(parts[:max_sentences]).strip()


def human_title_from_tool_name(name: str) -> str:
    words = [w for w in str(name).replace('_', ' ').split() if w]
    if not words:
        return 'Shellui tool'
    return ' '.join(w.capitalize() for w in words)


def tool_title(operation: dict[str, Any], tool_name: str) -> str:
    summary = str(operation.get('summary') or '').strip()
    if summary:
        return _first_sentences(summary, max_sentences=1) or human_title_from_tool_name(tool_name)
    return human_title_from_tool_name(tool_name)


def _strip_openapi_noise(text: str) -> str:
    """Drop drf-spectacular parameter dumps and ``key: type`` lines from descriptions."""
    lines: list[str] = []
    for raw in str(text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.match(r'^[\w.-]+\s*:\s*(string|integer|number|boolean|array|object)\b', line, re.I):
            continue
        if line.startswith('- ') and ':' in line[:80]:
            continue
        lines.append(line)
    joined = ' '.join(lines)
    return re.sub(r'\s+', ' ', joined).strip()


def tool_description(operation: dict[str, Any], *, method: str, access: dict[str, bool]) -> str:
    summary = str(operation.get('summary') or '').strip()
    body = _strip_openapi_noise(str(operation.get('description') or ''))
    parts: list[str] = []
    if summary:
        parts.append(_first_sentences(summary, max_sentences=1))
    if body:
        detail = _first_sentences(body, max_sentences=1)
        if detail and detail not in parts:
            parts.append(detail)
    if not parts:
        parts.append(f'Calls the {method.upper()} endpoint for this Shellui API operation.')
    text = ' '.join(parts)
    if access.get('destructive'):
        text = f'{text} This operation can delete or irreversibly change data.'
    elif not access.get('read_only') and method.upper() in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        text = f'{text} This operation can change company data.'
    return sanitize_shellui_copy(text)


def tool_annotations(operation: dict[str, Any], *, method: str, access: dict[str, bool]) -> dict[str, bool]:
    verb = method.upper()
    read_only = bool(access.get('read_only')) or verb in {'GET', 'HEAD'}
    destructive = bool(access.get('destructive')) or verb == 'DELETE'
    if not read_only and not destructive and verb in {'PUT', 'PATCH'}:
        destructive = True
    idempotent = read_only or verb in {'PUT', 'DELETE', 'HEAD'}
    if verb == 'POST' and not read_only:
        idempotent = False
    x_mcp = operation.get('x-mcp') if isinstance(operation.get('x-mcp'), dict) else {}
    if 'open_world' in x_mcp:
        open_world = bool(x_mcp.get('open_world'))
    else:
        op_id = str(operation.get('operationId') or '').lower()
        open_world = any(token in op_id for token in ('send', 'deliver', 'webhook', 'provider', 'external'))
    return {
        'readOnlyHint': read_only,
        'destructiveHint': destructive if not read_only else False,
        'idempotentHint': idempotent if not read_only else True,
        'openWorldHint': open_world,
    }


def _response_json_schema(operation: dict[str, Any], root: dict[str, Any]) -> dict[str, Any] | None:
    responses = operation.get('responses') if isinstance(operation.get('responses'), dict) else {}
    for status in ('200', '201', '202'):
        block = responses.get(status)
        if not isinstance(block, dict):
            continue
        content = block.get('content') if isinstance(block.get('content'), dict) else {}
        media = content.get('application/json') or content.get('application/vnd.api+json')
        if not isinstance(media, dict):
            continue
        schema = media.get('schema')
        if not isinstance(schema, dict):
            continue
        resolved = openapi_schema_to_json_schema(schema, root)
        if not resolved:
            continue
        if resolved.get('type') == 'object' or resolved.get('properties'):
            return normalize_output_schema(resolved)
        return normalize_output_schema(
            {
                'type': 'object',
                'properties': {'result': resolved},
                'required': ['result'],
                'additionalProperties': False,
            }
        )
    return None


def normalize_output_schema(schema: dict[str, Any]) -> dict[str, Any]:
    out = dict(schema)
    out.setdefault('type', 'object')
    if out.get('type') == 'object':
        out.setdefault('additionalProperties', False)
    return out


def enrich_input_schema_descriptions(
    input_schema: dict[str, Any],
    *,
    operation: dict[str, Any],
    path: str,
    method: str,
    root: dict[str, Any],
) -> dict[str, Any]:
    """Ensure proxy fields and nested properties carry OpenAPI-sourced descriptions."""
    props = input_schema.get('properties')
    if not isinstance(props, dict):
        return input_schema
    summary = sanitize_shellui_copy(str(operation.get('summary') or ''))
    if 'path' in props and not str((props['path'] or {}).get('description') or '').strip():
        props['path']['description'] = f'Fixed OpenAPI path for this tool ({path}).'
    if 'method' in props and not str((props['method'] or {}).get('description') or '').strip():
        props['method']['description'] = f'HTTP method ({method.upper()}).'
    if 'query' in props:
        q = props['query']
        if isinstance(q, dict) and not str(q.get('description') or '').strip():
            q['description'] = f'Query parameters for {summary or "this operation"}.'
    if 'body' in props:
        b = props['body']
        if isinstance(b, dict) and not str(b.get('description') or '').strip():
            b['description'] = f'JSON request body for {summary or "this operation"}.'
    if 'path_params' in props and isinstance(props['path_params'], dict):
        pp = props['path_params']
        if not str(pp.get('description') or '').strip():
            pp['description'] = 'Path template parameters for this request.'
        nested = pp.get('properties')
        if isinstance(nested, dict):
            for key, node in nested.items():
                if isinstance(node, dict) and not str(node.get('description') or '').strip():
                    node['description'] = f'Value for path parameter `{key}`.'
    _attach_parameter_examples(props, operation, root)
    return input_schema


def _attach_parameter_examples(
    props: dict[str, Any],
    operation: dict[str, Any],
    root: dict[str, Any],
) -> None:
    query_props = (props.get('query') or {}).get('properties') if isinstance(props.get('query'), dict) else None
    if not isinstance(query_props, dict):
        query_props = {}
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('in') != 'query':
            continue
        name = str(param.get('name') or '')
        if not name or name not in query_props:
            continue
        node = query_props[name]
        if not isinstance(node, dict):
            continue
        if 'example' in param and 'example' not in node:
            node['example'] = param['example']
        schema = param.get('schema') if isinstance(param.get('schema'), dict) else {}
        if 'example' in schema and 'example' not in node:
            node['example'] = schema['example']
        if node.get('enum') and 'description' in node:
            enums = ', '.join(repr(v) for v in node['enum'][:12])
            node['description'] = f"{node['description']} Allowed values: {enums}."


def apply_tool_presentation(
    tool: dict[str, Any],
    *,
    operation: dict[str, Any],
    method: str,
    path: str,
    root: dict[str, Any],
) -> dict[str, Any]:
    access = tool_access_flags(operation)
    meta = dict(tool.get('_meta') or {})
    meta['read_only'] = access['read_only']
    meta['destructive'] = access['destructive']
    tool['title'] = tool_title(operation, str(tool.get('name') or ''))
    tool['description'] = tool_description(operation, method=method, access=access)
    tool['annotations'] = tool_annotations(operation, method=method, access=access)
    output = _response_json_schema(operation, root)
    if output:
        tool['outputSchema'] = output
    if isinstance(tool.get('inputSchema'), dict):
        tool['inputSchema'] = enrich_input_schema_descriptions(
            tool['inputSchema'],
            operation=operation,
            path=path,
            method=method,
            root=root,
        )
    tool['_meta'] = meta
    return tool


def shellui_gateway_instructions(
    *,
    title: str,
    connected_services: list[str],
    local_service_id: str = 'ai',
) -> str:
    services = ', '.join(connected_services) if connected_services else 'none'
    prefixes = ', '.join(f'{sid}_' for sid in sorted(set(connected_services)))
    return sanitize_shellui_copy(
        f'{title}\n'
        'Shellui exposes company-scoped HTTP APIs as MCP tools. Each tool maps to one OpenAPI operation.\n'
        f'Connected services for this agent: {services}.\n'
        f'Every tool name starts with a service id ({prefixes or "service_"}), then verb and resource '
        '(for example ai_list_services, email_send_message).\n'
        'Prefer list_* tools before get_* detail calls. Requests are scoped to the company in the MCP URL '
        '(/c/<company_id>/mcp).\n'
        'Use annotations.readOnlyHint and annotations.destructiveHint to decide when to confirm with the user. '
        'Use ai_list_services for per-service MCP URLs and resource-bound tokens.'
    )


def inspect_tool_presentation(tool: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(path, category)`` presentation gaps."""
    issues: list[tuple[str, str]] = []
    name = str(tool.get('name') or '')
    title = str(tool.get('title') or '').strip()
    if not title:
        issues.append(('_tool.title', 'missing_title'))
    desc = str(tool.get('description') or '').strip()
    if len(desc) < 24:
        issues.append(('_tool.description', 'missing_description'))
    if _EM_EN_DASH.search(desc) or _EM_EN_DASH.search(title):
        issues.append(('_tool.copy', 'shellui_copy_dash'))
    if 'shellui' in desc.lower() and 'Shellui' not in desc:
        issues.append(('_tool.copy', 'shellui_copy_brand'))
    annotations = tool.get('annotations')
    if not isinstance(annotations, dict):
        issues.append(('_tool.annotations', 'missing_annotations'))
    else:
        for key in ('readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'):
            if key not in annotations:
                issues.append(('_tool.annotations', 'incomplete_annotations'))
    meta = tool.get('_meta') or {}
    if meta.get('has_json_response') and not tool.get('outputSchema'):
        issues.append(('_tool.outputSchema', 'missing_output_schema'))
    return issues


def presentation_coverage(tools: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(tools)
    with_title = sum(1 for t in tools if str(t.get('title') or '').strip())
    with_desc = sum(1 for t in tools if len(str(t.get('description') or '').strip()) >= 24)
    with_ann = sum(1 for t in tools if isinstance(t.get('annotations'), dict))
    with_output = sum(1 for t in tools if isinstance(t.get('outputSchema'), dict))
    prop_total = 0
    prop_described = 0
    for tool in tools:
        schema = tool.get('inputSchema') if isinstance(tool.get('inputSchema'), dict) else {}
        props = schema.get('properties') if isinstance(schema.get('properties'), dict) else {}
        for key, node in props.items():
            if key in {'path', 'method'}:
                continue
            if not isinstance(node, dict):
                continue
            prop_total += 1
            if str(node.get('description') or '').strip():
                prop_described += 1
            nested = node.get('properties')
            if isinstance(nested, dict):
                for sub_key, sub in nested.items():
                    if isinstance(sub, dict):
                        prop_total += 1
                        if str(sub.get('description') or '').strip():
                            prop_described += 1
    return {
        'tools': total,
        'with_title': with_title,
        'with_description': with_desc,
        'with_annotations': with_ann,
        'with_output_schema': with_output,
        'input_properties': prop_total,
        'input_properties_with_description': prop_described,
    }
