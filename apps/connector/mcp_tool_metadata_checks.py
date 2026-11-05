"""Shared MCP tools/list metadata checks (gateway export names and presentation)."""

from __future__ import annotations

import re

SERVICE_IDS = frozenset({'ai', 'identity', 'storage', 'hosting', 'email', 'saas'})
ANNOTATION_KEYS = ('readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint')
_API_VERSION_IN_COPY = re.compile(r'\b(?:api\s*)?v\s*\d+\b|\bapi\s+v\s*\d+\b|/api/v\d+/|api_v\d+', re.I)

# ``{service}_{verb}_{noun...}`` snake_case; no version segments or numeric collision suffixes.
GATEWAY_TOOL_NAME_RE = re.compile(
    r'^(?:ai|identity|storage|hosting|email|saas)_[a-z][a-z0-9]*(?:_[a-z][a-z0-9]+)+$'
)


def validate_gateway_tool_name(name: str) -> list[str]:
    issues: list[str] = []
    if not name:
        return ['empty']
    if 'api_v1' in name or 'api_v' in name or '__' in name:
        issues.append('forbidden_substring')
    if re.search(r'_\d+$', name):
        issues.append('numeric_collision_suffix')
    if not GATEWAY_TOOL_NAME_RE.match(name):
        issues.append('pattern')
    service = name.split('_', 1)[0]
    if service not in SERVICE_IDS:
        issues.append('unknown_service')
    return issues


def validate_tool_metadata(tool: dict) -> list[str]:
    """Return human-readable failure lines for one tool dict from tools/list."""
    name = str(tool.get('name') or '')
    errors: list[str] = []
    for code in validate_gateway_tool_name(name):
        if code == 'forbidden_substring':
            errors.append(f'{name}: invalid tool name (api_v or double underscore)')
        elif code == 'numeric_collision_suffix':
            errors.append(f'{name}: tool name uses numeric collision suffix')
        elif code == 'pattern':
            errors.append(f'{name}: tool name must match service_verb_noun snake_case')
        elif code == 'empty':
            errors.append('unnamed tool')
        elif code == 'unknown_service':
            errors.append(f'{name}: unknown service prefix')
    title = str(tool.get('title') or '').strip()
    if len(title) < 3:
        errors.append(f'{name}: missing title')
    elif _API_VERSION_IN_COPY.search(title):
        errors.append(f'{name}: title must not include API version noise')
    desc = str(tool.get('description') or '').strip()
    if len(desc) < 20:
        errors.append(f'{name}: description too short')
    elif _API_VERSION_IN_COPY.search(desc):
        errors.append(f'{name}: description must not include API version noise')
    service = name.split('_', 1)[0] if '_' in name else ''
    if service in SERVICE_IDS:
        from apps.connector.mcp_service_display import mcp_service_display_name

        label = mcp_service_display_name(service)
        lower = title.lower()
        if not (lower.startswith(f'{label.lower()}:') or lower.startswith(f'{label.lower()} ')):
            errors.append(f'{name}: title must start with service name ({label})')
    ann = tool.get('annotations')
    if not isinstance(ann, dict):
        errors.append(f'{name}: missing annotations')
    else:
        for key in ANNOTATION_KEYS:
            if key not in ann:
                errors.append(f'{name}: annotations.{key} missing')
    return errors


def validate_tools_list(tools: list[dict]) -> list[str]:
    errors: list[str] = []
    for tool in tools:
        if isinstance(tool, dict):
            errors.extend(validate_tool_metadata(tool))
    return errors
