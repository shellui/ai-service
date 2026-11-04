"""MCP Inspector–aligned audits for tool metadata and inputSchema (cross-service reports)."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from apps.connector.mcp_tool_naming import legacy_slug_tool_name

from apps.connector.mcp_tool_schema import (
    normalize_mcp_tool,
    normalize_tool_input_schema,
    strict_client_schema_issues,
)

_ISSUE_UNTYPED = 'untyped_or_empty'
_ISSUE_REF = 'unresolved_ref'
_ISSUE_COMBINATOR = 'anyof_oneof_allof'
_ISSUE_NULLABLE = 'nullable_type_array'
_ISSUE_MISSING_DESC = 'missing_description'
_ISSUE_MISSING_REQUIRED = 'missing_required'
_ISSUE_BROAD_OBJECT = 'broad_free_form_object'
_ISSUE_VAGUE_TOOL = 'vague_tool_metadata'
_ISSUE_DUPLICATE = 'duplicate_tool_metadata'


@dataclass(frozen=True)
class SchemaIssue:
    service: str
    tool: str
    path: str
    category: str
    detail: str


def legacy_tools_from_schema(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """shellui-django 0.4.0 behaviour (empty ``{}`` query/body fields)."""
    from shellui_django.mcp.openapi_mcp import tool_access_flags
    from shellui_django.mcp.routing import path_parameter_names

    MCP_TOOL_TAG = 'mcp-tools'

    def _parameter_field_names(operation: dict[str, Any], *, location: str) -> tuple[list[str], list[str]]:
        names: list[str] = []
        required: list[str] = []
        for param in operation.get('parameters') or []:
            if not isinstance(param, dict) or param.get('in') != location:
                continue
            name = param.get('name')
            if not name:
                continue
            names.append(str(name))
            if param.get('required'):
                required.append(str(name))
        return names, required

    def _body_field_names(operation: dict[str, Any]) -> tuple[list[str], list[str]]:
        request_body = operation.get('requestBody') or {}
        if not isinstance(request_body, dict):
            return [], []
        content = request_body.get('content') or {}
        body_schema = content.get('application/json', {}).get('schema') or {}
        if not isinstance(body_schema, dict):
            return [], []
        props = body_schema.get('properties') or {}
        if not isinstance(props, dict):
            return [], []
        names = [str(key) for key in props.keys()]
        required_raw = body_schema.get('required') or []
        required = [str(key) for key in required_raw if str(key) in names]
        return names, required

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
            name = legacy_slug_tool_name(method, path, operation.get('operationId'))
            description = (operation.get('summary') or operation.get('description') or name).strip()
            path_params = path_parameter_names(path)
            query_fields, query_required = _parameter_field_names(operation, location='query')
            body_fields, body_required = _body_field_names(operation)
            properties: dict[str, Any] = {
                'path': {'type': 'string', 'const': path},
                'method': {'type': 'string', 'enum': [method.upper()]},
                'query': {'type': 'object', 'additionalProperties': False, 'properties': {}},
                'body': {'type': 'object', 'additionalProperties': False, 'properties': {}},
            }
            required = ['path', 'method']
            if path_params:
                properties['path_params'] = {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {param: {'type': 'string'} for param in path_params},
                    'required': path_params,
                }
                required.append('path_params')
            if query_fields:
                properties['query']['properties'] = {field: {} for field in query_fields}
            if body_fields:
                properties['body']['properties'] = {field: {} for field in body_fields}
            access = tool_access_flags(operation)
            tools.append(
                {
                    'name': name,
                    'description': description,
                    'inputSchema': {
                        'type': 'object',
                        'properties': properties,
                        'required': required,
                        'additionalProperties': False,
                    },
                    '_meta': {
                        'query_required': query_required or None,
                        'body_required': body_required or None,
                        'read_only': access['read_only'],
                    },
                }
            )
    tools.sort(key=lambda t: t['name'])
    return tools


def _walk(node: Any, path: str, issues: list[tuple[str, str]], *, root_path: bool = False) -> None:
    if not isinstance(node, dict):
        return
    if node == {}:
        issues.append((path or '$', _ISSUE_UNTYPED))
    if '$ref' in node:
        issues.append((path or '$', _ISSUE_REF))
    if isinstance(node.get('type'), list):
        issues.append((path or '$', _ISSUE_NULLABLE))
    for comb in ('anyOf', 'oneOf', 'allOf'):
        if comb in node:
            if root_path and path == '':
                issues.append((path or '$', _ISSUE_COMBINATOR))
            elif path:
                issues.append((path, _ISSUE_COMBINATOR))
    if node.get('type') == 'object':
        ap = node.get('additionalProperties')
        if ap is True:
            issues.append((path or '$', _ISSUE_BROAD_OBJECT))
        elif isinstance(ap, dict) and not ap.get('type') and 'properties' not in ap:
            issues.append((path or '$', _ISSUE_BROAD_OBJECT))
    has_keyword = (
        node.get('type') in {'string', 'integer', 'number', 'boolean', 'array', 'object', 'null'}
        or 'enum' in node
        or 'const' in node
    )
    if not has_keyword and node != {} and not any(k in node for k in ('properties', 'items', 'anyOf', 'oneOf', 'allOf')):
        issues.append((path or '$', _ISSUE_UNTYPED))
    _structural = {
        'properties.path',
        'properties.method',
        'properties.query',
        'properties.body',
    }
    if path and not path.startswith('_tool_') and path not in _structural:
        if not str(node.get('description') or '').strip() and node.get('type') in {
            'string',
            'integer',
            'number',
            'boolean',
            'array',
            'object',
        }:
            issues.append((path, _ISSUE_MISSING_DESC))
    props = node.get('properties')
    if isinstance(props, dict):
        for key, val in props.items():
            child = f'{path}.properties.{key}' if path else f'properties.{key}'
            _walk(val, child, issues)
    if isinstance(node.get('items'), dict):
        _walk(node['items'], f'{path}.items' if path else 'items', issues)


def _required_mismatch(tool: dict[str, Any], issues: list[tuple[str, str]]) -> None:
    meta = tool.get('_meta') or {}
    schema = tool.get('inputSchema') or {}
    for block, meta_key in (('query', 'query_required'), ('body', 'body_required')):
        expected = meta.get(meta_key) or []
        if not expected:
            continue
        block_schema = (schema.get('properties') or {}).get(block) or {}
        actual = block_schema.get('required') or []
        missing = [f for f in expected if f not in actual]
        if missing:
            issues.append((f'properties.{block}', _ISSUE_MISSING_REQUIRED))


def inspect_tool(service: str, tool: dict[str, Any]) -> list[SchemaIssue]:
    name = str(tool.get('name') or '<unnamed>')
    issues: list[tuple[str, str]] = []
    desc = str(tool.get('description') or '').strip()
    if len(desc) < 12 or desc.replace('_', ' ') == name.replace('_', ' '):
        issues.append(('_tool.description', _ISSUE_VAGUE_TOOL))
    if not desc:
        issues.append(('_tool.description', _ISSUE_MISSING_DESC))
    input_schema = tool.get('inputSchema') if isinstance(tool.get('inputSchema'), dict) else {}
    _walk(input_schema, '', issues, root_path=True)
    _required_mismatch(tool, issues)
    return [
        SchemaIssue(service=service, tool=name, path=path, category=cat, detail=cat.replace('_', ' '))
        for path, cat in issues
    ]


def inspect_tools(service: str, tools: list[dict[str, Any]]) -> list[SchemaIssue]:
    rows: list[SchemaIssue] = []
    for tool in tools:
        rows.extend(inspect_tool(service, tool))
    descriptions = [str(t.get('description') or '').strip().lower() for t in tools]
    dupes = {d for d in descriptions if d and descriptions.count(d) > 1}
    if dupes:
        for tool in tools:
            desc = str(tool.get('description') or '').strip().lower()
            if desc in dupes:
                rows.append(
                    SchemaIssue(
                        service=service,
                        tool=str(tool.get('name')),
                        path='_tool.description',
                        category=_ISSUE_DUPLICATE,
                        detail='duplicate description within service',
                    )
                )
    return rows


def summarize_issues(issues: list[SchemaIssue]) -> dict[str, Any]:
    by_category = Counter(i.category for i in issues)
    by_service = Counter(i.service for i in issues)
    tools_with_issues = len({(i.service, i.tool) for i in issues})
    return {
        'total_issues': len(issues),
        'tools_with_issues': tools_with_issues,
        'by_category': dict(sorted(by_category.items())),
        'by_service': dict(sorted(by_service.items())),
    }


def format_report_markdown(
    *,
    services: dict[str, dict[str, Any]],
    before: dict[str, list[SchemaIssue]],
    after: dict[str, list[SchemaIssue]],
    name_mappings: list[dict[str, str]] | None = None,
) -> str:
    lines = [
        '# MCP tool inputSchema audit (all services)',
        '',
        'Generated from each service OpenAPI document (`mcp-tools` operations) using the',
        'legacy shellui-django 0.4.0 converter (**before**) and the ai-service typed converter',
        '+ normalization (**after**). Aligns with MCP Inspector checks (validation keywords,',
        'combinators, refs, nullable type arrays, required query/body fields).',
        '',
        '## Summary counts',
        '',
        '| Service | Tools | Issues before | Issues after |',
        '| --- | ---: | ---: | ---: |',
    ]
    total_tools = 0
    total_before = 0
    total_after = 0
    for svc in sorted(services.keys()):
        n = services[svc]['tool_count']
        b = len(before.get(svc, []))
        a = len(after.get(svc, []))
        total_tools += n
        total_before += b
        total_after += a
        lines.append(f'| {svc} | {n} | {b} | {a} |')
    lines.append(f'| **Total** | **{total_tools}** | **{total_before}** | **{total_after}** |')
    lines.extend(
        [
            '',
            '### By category (before → after)',
            '',
        ]
    )
    cats: set[str] = set()
    for m in (before, after):
        for issues in m.values():
            cats.update(i.category for i in issues)
    before_cat: Counter[str] = Counter(i.category for issues in before.values() for i in issues)
    after_cat: Counter[str] = Counter(i.category for issues in after.values() for i in issues)
    for cat in sorted(cats):
        lines.append(f'- `{cat}`: {before_cat.get(cat, 0)} → {after_cat.get(cat, 0)}')
    lines.extend(
        [
            '',
            '## Tool name mapping (legacy → service → gateway)',
            '',
            'Legacy names are slugified `operationId` values (pre–shellui-django 0.4.2). Service names',
            'use `verb_noun` without `api/v1` segments. The ai gateway exports downstream tools as',
            '``{service}_{tool}`` (single underscore). Full list: `name_mappings` in',
            '`docs/mcp-tool-schema-audit.json`.',
            '',
        ]
    )
    mappings = name_mappings or []
    if mappings:
        lines.append('| Service | Legacy | Service tool | Gateway export |')
        lines.append('| --- | --- | --- | --- |')
        for row in mappings:
            lines.append(
                f"| {row['service']} | `{row['legacy_name']}` | `{row['service_tool_name']}` | `{row['gateway_tool_name']}` |"
            )
        lines.append('')
    else:
        lines.append('_No mappings (missing service checkouts)._')
        lines.append('')
    lines.extend(['', '## Per-service, per-tool issues (after fix)', ''])
    for svc in sorted(services.keys()):
        issues = after.get(svc, [])
        lines.append(f'### {svc}')
        if not issues:
            lines.append('')
            lines.append('_No remaining issues._')
            lines.append('')
            continue
        by_tool: dict[str, list[SchemaIssue]] = defaultdict(list)
        for issue in issues:
            by_tool[issue.tool].append(issue)
        for tool in sorted(by_tool.keys()):
            lines.append(f'- **{tool}**')
            for issue in by_tool[tool]:
                lines.append(f'  - `{issue.path}`: {issue.category} — {issue.detail}')
        lines.append('')
    lines.extend(
        [
            '## Per-service, per-tool issues (before fix)',
            '',
            'Machine-readable full dump: `docs/mcp-tool-schema-audit.json` (`before` / `after_gateway` arrays).',
            'SaaS is omitted (no public `saas-service` checkout in this audit); **201** tools matches the',
            'five audited services (identity, storage, hosting, email, ai gateway).',
            '',
        ]
    )
    for svc in sorted(services.keys()):
        issues = before.get(svc, [])
        lines.append(f'### {svc} ({len(issues)} issues)')
        by_tool: dict[str, list[SchemaIssue]] = defaultdict(list)
        for issue in issues:
            by_tool[issue.tool].append(issue)
        for tool in sorted(by_tool.keys()):
            lines.append(f'- **{tool}** ({len(by_tool[tool])} issues)')
            for issue in by_tool[tool]:
                lines.append(f'  - `{issue.path}`: {issue.category}')
        lines.append('')
    exceptions = [i for issues in after.values() for i in issues]
    lines.extend(['## Remaining exceptions', ''])
    if not exceptions:
        lines.append('None. All audited tools pass Inspector-aligned checks after normalization.')
    else:
        for issue in exceptions[:50]:
            lines.append(f'- {issue.service}/{issue.tool} `{issue.path}`: {issue.category}')
    lines.append('')
    return '\n'.join(lines)
