"""MCP tool presentation (title, description, annotations, outputSchema) from OpenAPI."""

from __future__ import annotations

import re
from typing import Any

from shellui_django.mcp.openapi_mcp import tool_access_flags

from apps.connector.mcp_tool_schema import openapi_schema_to_json_schema

_SENTENCE_END = re.compile(r'(?<=[.!?])\s+')
_EM_EN_DASH = re.compile(r'[\u2013\u2014\u2012]')
_SHELLUI_WORD = re.compile(r'\bshellui\b', re.I)
_API_PATH_SNIPPET = re.compile(r'/api/v\d+/', re.I)
_API_VERSION_PHRASE = re.compile(r'\b(?:api\s*)?v\s*\d+\b|\bapi\s+v\s*\d+\b', re.I)
_API_V1_UNDERSCORE = re.compile(r'\bapi_v\d+_?', re.I)
_COMPANY_SUFFIX_RE = re.compile(r' \([^()]+\)$')


def strip_presentation_noise(text: str) -> str:
    """Remove API version paths and ``API V1``-style phrases from titles and descriptions."""
    out = sanitize_shellui_copy(str(text or ''))
    if not out:
        return ''
    out = _API_PATH_SNIPPET.sub('', out)
    out = _API_V1_UNDERSCORE.sub('', out)
    out = _API_VERSION_PHRASE.sub('', out)
    out = re.sub(r'\s+', ' ', out).strip(' ,:-')
    return sanitize_shellui_copy(out)


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
        title = _first_sentences(summary, max_sentences=1) or human_title_from_tool_name(tool_name)
    else:
        title = human_title_from_tool_name(tool_name)
    return strip_presentation_noise(title)


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
    text = strip_presentation_noise(' '.join(parts))
    if access.get('destructive'):
        text = f'{text} This operation can delete or irreversibly change data.'
    elif not access.get('read_only') and method.upper() in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        text = f'{text} This operation can change company data.'
    return strip_presentation_noise(text)


def tool_annotations(operation: dict[str, Any], *, method: str, access: dict[str, bool]) -> dict[str, bool]:
    verb = method.upper()
    read_only = bool(access.get('read_only')) or verb in {'GET', 'HEAD'}
    # Destructive follows the registry (x-mcp / recovered operation id), not the verb.
    # PUT and PATCH replace fields; only DELETE and explicitly destructive operations
    # are destructive. Marking every update destructive hid session grants and made
    # full-access agents ask for approval on ordinary edits.
    destructive = bool(access.get('destructive')) or verb == 'DELETE'
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


def _gateway_service_id(tool_name: str) -> str:
    name = str(tool_name or '').strip()
    if '_' not in name:
        return ''
    return name.split('_', 1)[0].lower()


def _title_has_service_prefix(title: str, service_label: str) -> bool:
    lower = title.lower()
    label = service_label.lower()
    return lower.startswith(f'{label}:') or lower.startswith(f'{label} ') or lower == label


def ensure_service_first_title(title: str, *, tool_name: str) -> str:
    """Prefix titles with the Shellui service name (``Storage: …``, ``Email: …``)."""
    from apps.connector.mcp_service_display import mcp_service_display_name

    service_id = _gateway_service_id(tool_name)
    service_label = mcp_service_display_name(service_id) if service_id else ''
    raw = str(title or '').strip()
    if not raw:
        raw = human_title_from_tool_name(tool_name)
    suffix = ''
    match = _COMPANY_SUFFIX_RE.search(raw)
    if match:
        suffix = match.group(0)
        raw = raw[: match.start()].rstrip()
    cleaned = strip_presentation_noise(raw)
    if not service_label:
        return sanitize_shellui_copy(f'{cleaned}{suffix}'.strip())
    if _title_has_service_prefix(cleaned, service_label):
        return sanitize_shellui_copy(f'{cleaned}{suffix}'.strip())
    return sanitize_shellui_copy(f'{service_label}: {cleaned}{suffix}'.strip())


def apply_gateway_tool_presentation(tool: dict[str, Any], *, company_label: str) -> dict[str, Any]:
    """Final gateway ``tools/list`` copy: service-first title, no API version noise, company scope."""
    from copy import deepcopy

    out = deepcopy(tool)
    name = str(out.get('name') or '')
    raw_title = str(out.get('title') or '').strip()
    if not raw_title:
        # Humanize the local verb_noun, not ``identity_create_groups``. A title that
        # merely starts with the service word would skip the ``Identity:`` prefix.
        service_id = _gateway_service_id(name)
        local = name[len(service_id) + 1 :] if service_id and name.startswith(f'{service_id}_') else name
        raw_title = human_title_from_tool_name(local)
    title = ensure_service_first_title(raw_title, tool_name=name)
    out['title'] = title
    desc = strip_presentation_noise(str(out.get('description') or ''))
    if desc:
        out['description'] = desc
    return apply_company_scope_to_tool(out, company_label=company_label)


def apply_company_scope_to_tool(tool: dict[str, Any], *, company_label: str) -> dict[str, Any]:
    """Make multi-company MCP connections distinguishable in clients (title + description)."""
    from copy import deepcopy

    label = sanitize_shellui_copy(str(company_label or '').strip())
    if not label:
        return tool
    out = deepcopy(tool)
    suffix = f' ({label})'
    title = str(out.get('title') or '').strip()
    if title and not title.endswith(suffix):
        out['title'] = sanitize_shellui_copy(f'{title}{suffix}')
    scope_line = sanitize_shellui_copy(
        f'This call applies to company {label}. '
        'Company scope comes from your MCP connection and agent token, not from tool arguments.'
    )
    desc = str(out.get('description') or '').strip()
    if label not in desc:
        out['description'] = sanitize_shellui_copy(f'{scope_line} {desc}'.strip()) if desc else scope_line
    return out


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
        'Shellui exposes company-scoped HTTP APIs as MCP tools. The default tools/list is a short discovery set, '
        'not every operation.\n'
        'Workflow: call ai_list_services, then ai_search_tools with a short phrase, then tools/call or ai_call_tool. '
        'Use ai_describe_tool when you need the full input schema. '
        'If a tool result says approval pending, show the approval link to the user. '
        'After they approve, call the same tool again. ai_get_approval reads the decision without running the tool.\n'
        f'Connected services for this agent: {services}.\n'
        f'Tool names start with a service id ({prefixes or "service_"}), then verb and resource '
        '(for example identity_list_users, hosting_list_apps).\n'
        'Requests are scoped to the company in the MCP URL (/c/<company_id>/mcp). '
        'A direct tools/call of a tool that is not in the default list still works.\n'
        'Add ?tools=all on the MCP URL, or pass {"tools": "all"} to tools/list, when you need the full catalog. '
        'Use annotations.readOnlyHint and annotations.destructiveHint to decide when to confirm with the user.'
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
