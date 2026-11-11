"""Trustworthy MCP call-log audit fields for identity personal activity (no secrets).

Maps internal ``log_result`` / HTTP status to a small outcome enum; derives display
fields from tool registry metadata and validated agent JWT claims only.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from apps.connector.mcp_audit_codes import error_code_from_http, sanitize_error_code
from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_tool_presentation import strip_presentation_noise

# Public activity vocabulary (identity new writes). Internal log_result may still use ``pending``.
OUTCOMES = frozenset({'allowed', 'failed', 'denied', 'pending_approval', 'session_used'})


def legacy_result_token(*, outcome: str) -> str:
    """Short legacy ``result`` string kept on in-memory audit rows."""
    o = str(outcome or '').strip().lower()
    if o == 'allowed':
        return 'success'
    if o == 'session_used':
        return 'success'
    if o == 'failed':
        return 'error'
    if o == 'denied':
        return 'denied'
    if o in {'pending_approval', 'pending'}:
        return 'pending_approval'
    return 'error'


def _canonical_log_result(*, outcome: str, status: int, is_error: bool | None) -> str:
    """Stable ``log_result`` for forwarded rows (tests + Identity ingest) after outcome is computed."""
    o = str(outcome or '').strip().lower()
    if o == 'pending_approval':
        return 'pending_approval'
    if o == 'denied':
        return 'denied'
    if o in {'allowed', 'session_used'}:
        return 'success'
    if o == 'failed':
        return 'error'
    code = int(status or 0)
    if is_error is True:
        return 'error'
    if is_error is False and 200 <= code < 400:
        return 'success'
    return 'error'


def outcome_from_audit(*, log_result: str | None, status: int | None, is_error: bool | None) -> str:
    """Map gateway bookkeeping to a fixed outcome enum (no substring heuristics on error text)."""
    lr = str(log_result or '').strip().lower()
    if lr in {'client_session_allowed'}:
        return 'session_used'
    if lr in {'identity_approved'}:
        return 'allowed'
    if lr in {'approved', 'client_allowed', 'success'}:
        return 'allowed'
    if lr in {'pending', 'pending_approval'}:
        return 'pending_approval'
    if lr in {'denied', 'client_denied'}:
        return 'denied'
    if lr in {'expired'}:
        return 'failed'
    code = int(status or 0)
    # MCP JSON-RPC can return HTTP 200 with isError true; classify as failed, not allowed.
    if lr == 'error' or is_error is True:
        return 'failed'
    # Unknown log_result with HTTP success: fail closed unless explicitly not an error.
    if 200 <= code < 400:
        if is_error is False:
            return 'allowed'
        return 'failed'
    if code == 403:
        return 'denied'
    if code == 401:
        return 'denied'
    return 'failed'


def _tool_traits(tool: dict[str, Any] | None, *, method: str) -> tuple[bool, bool]:
    if not isinstance(tool, dict):
        return False, False
    ann = tool.get('annotations') if isinstance(tool.get('annotations'), dict) else {}
    read_only = bool(ann.get('readOnlyHint'))
    destructive = bool(ann.get('destructiveHint'))
    meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
    if meta.get('read_only') is True:
        read_only = True
    if meta.get('destructive') is True:
        destructive = True
    return read_only, destructive


def access_kind_from_tool(tool: dict[str, Any] | None, *, method: str) -> str:
    """Derive access kind from explicit registry flags and HTTP method only (no infer from name)."""
    read_only, destructive = _tool_traits(tool, method=method)
    raw_m = str(method or '').strip()
    if not raw_m:
        return 'write'
    m = raw_m.upper()
    if m in {'GET', 'HEAD', 'OPTIONS'}:
        return 'read'
    if destructive:
        return 'destructive'
    if read_only:
        return 'read'
    return 'write'


def _path_template_for_audit(meta: dict[str, Any]) -> str:
    p = str(meta.get('path') or '').strip()
    if not p:
        return ''
    return p.split('?', 1)[0].strip() or ''


_OP_TITLE_BROKER_RE = re.compile(r'\b(broker|queue|ask)\b', re.I)

# Local audit labels only; Identity ``develop`` derives its own ``resource_label`` for ingest.
_RESOURCE_LABEL_IDENTITY_CHARS = re.compile(r'[^\w\- ./:~+@%]', re.UNICODE)


def _neutral_operation_title(export_name: str) -> str:
    base = str(export_name or '').strip() or 'tool'
    if re.match(r'^operation\b', base, re.I):
        return base[:200]
    return f'Operation {base}'[:200]


def operation_title_for_audit(
    tool: dict[str, Any] | None,
    *,
    export_name: str,
    method: str,
) -> str:
    """Trusted title: OpenAPI ``operation_summary`` from registry ``_meta`` only (no tool.title / downstream text)."""
    if not isinstance(tool, dict):
        return _neutral_operation_title(export_name)
    meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
    op_sum = str(meta.get('operation_summary') or '').strip()
    if op_sum:
        if _OP_TITLE_BROKER_RE.search(op_sum):
            return _neutral_operation_title(export_name)
        return strip_presentation_noise(op_sum)[:200]
    return _neutral_operation_title(export_name)


def safe_route_path_for_audit(raw: object) -> str:
    """Strip query/fragment and scheme for audit path and resource label (no client-controlled query leakage)."""
    s = str(raw or '').strip()
    if not s:
        return ''
    if '://' in s:
        parts = urlsplit(s)
        path = parts.path or ''
    else:
        path = s.split('#', 1)[0].split('?', 1)[0]
    return path.strip()[:512]


def resource_label_safe(*, method: str, path: str, tool: dict[str, Any] | None, export_name: str = '') -> str:
    m = str(method or '').strip().upper()[:16] or 'GET'
    meta = tool.get('_meta') if isinstance(tool, dict) and isinstance(tool.get('_meta'), dict) else {}
    tmpl = _path_template_for_audit(meta)
    if not tmpl:
        # No registered route template: stable gateway export id only (no raw path / query).
        en = str(export_name or '').strip() or (str(tool.get('name') or '').strip() if isinstance(tool, dict) else '')
        tmpl = f'gateway:{en}' if en else 'gateway:tool'
    # No whitespace: keep local labels charset-safe (forwarded path only; no client ``resource_label``).
    avail = max(1, 120 - len(m) - 1)
    tmpl = tmpl.strip()[:avail]
    label = f'{m}-{tmpl}'.strip('-')
    label = _RESOURCE_LABEL_IDENTITY_CHARS.sub('_', label)
    return label[:120]


def build_call_audit_log(
    *,
    agent_claims: dict[str, Any],
    service_id: str,
    export_name: str,
    tool: dict[str, Any] | None,
    method: str,
    path: str,
    log_result: str | None,
    status: int,
    is_error: bool | None = None,
    approval_id: str | None = None,
    legacy_result: str | None = None,
    error_code: str | None = None,
) -> dict[str, Any]:
    cid = strict_numeric_company_id(agent_claims.get('company_id'))
    claim_service = str(agent_claims.get('service') or '').strip()
    svc = str(service_id or '').strip()
    if claim_service and svc and claim_service != svc:
        outcome = 'failed'
    else:
        outcome = outcome_from_audit(log_result=log_result, status=status, is_error=is_error)
    access_kind = access_kind_from_tool(tool, method=method)
    op_title = operation_title_for_audit(tool, export_name=export_name, method=method)
    meta = tool.get('_meta') if isinstance(tool, dict) and isinstance(tool.get('_meta'), dict) else {}
    path_tmpl = _path_template_for_audit(meta)
    safe_path = path_tmpl if path_tmpl else ''
    rid = str(approval_id or '').strip()
    agent_name = str(agent_claims.get('agent_name') or '').strip()[:200]
    company_name = str(agent_claims.get('company_name') or '').strip()[:200]

    entry: dict[str, Any] = {
        'agent_id': str(agent_claims.get('agent_id') or '').strip()[:128],
        'company_id': int(cid) if cid is not None else 0,
        'company_name': company_name,
        'agent_name': agent_name,
        'service': str(service_id or '')[:64],
        'tool': str(export_name or '')[:256],
        'tool_export_id': str(export_name or '')[:256],
        'operation_title': op_title,
        'method': str(method or '')[:16],
        'path': safe_path,
        'resource_label': resource_label_safe(method=method, path=path, tool=tool, export_name=export_name),
        'access_kind': access_kind,
        'status': int(status),
        'outcome': outcome if outcome in OUTCOMES else 'failed',
        'duration_ms': 0,
    }
    ec_kw = error_code
    ec = sanitize_error_code(ec_kw) if ec_kw is not None and str(ec_kw).strip() else None
    if ec is None:
        ec = error_code_from_http(status=int(status), is_error=is_error)
    if ec:
        entry['error_code'] = ec
    if rid:
        entry['approval_id'] = rid[:64]
    final_outcome = str(entry.get('outcome') or 'failed').strip().lower()
    entry['log_result'] = _canonical_log_result(
        outcome=final_outcome,
        status=int(status),
        is_error=is_error,
    )
    if is_error is not None:
        entry['is_error'] = bool(is_error)
    elif final_outcome in {'allowed', 'session_used'}:
        entry['is_error'] = False
    elif final_outcome in {'failed', 'denied'}:
        entry['is_error'] = True
    else:
        entry['is_error'] = None
    lr = str(legacy_result or '').strip()[:32]
    if lr:
        entry['result'] = lr
    elif not entry.get('result'):
        entry['result'] = legacy_result_token(outcome=outcome)
    read_only, destructive = _tool_traits(tool, method=method)
    entry['read_only_hint'] = bool(read_only)
    entry['destructive_hint'] = bool(destructive)
    return entry
