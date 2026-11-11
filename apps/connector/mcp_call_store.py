"""Persist one redacted row per gateway tools/call. Writes never raise."""

from __future__ import annotations

import contextvars
import json
import logging
import re
from typing import Any

from apps.connector.mcp_audit_codes import sanitize_error_code
from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_discovery import redact_arguments
from apps.connector.mcp_setup_context import is_global_delegated_claims

logger = logging.getLogger(__name__)

SERVICES = frozenset({'identity', 'storage', 'hosting', 'email', 'saas', 'ai'})
_ERROR_TRANSPORT_CODES = frozenset({'timeout', 'upstream_error', 'identity_unreachable'})
_CHANNELS = frozenset({'form', 'link', 'none'})
_BEARER_RE = re.compile(r'(?i)(bearer\s+)\S+')
_LONG_TOKEN_RE = re.compile(r'\b[A-Za-z0-9_\-]{24,}\b')

_logged: contextvars.ContextVar[bool] = contextvars.ContextVar('mcp_call_logged', default=False)
_wrapper_tool: contextvars.ContextVar[str] = contextvars.ContextVar('mcp_call_wrapper', default='')
_export_name: contextvars.ContextVar[str] = contextvars.ContextVar('mcp_call_export', default='')
_arguments: contextvars.ContextVar[dict | None] = contextvars.ContextVar('mcp_call_arguments', default=None)
_approval_note: contextvars.ContextVar[dict | None] = contextvars.ContextVar('mcp_call_approval', default=None)


def begin_gateway_tool_call() -> None:
    """Start of one HTTP tools/call. Nested ai_call_tool must not call this again."""
    _logged.set(False)
    _wrapper_tool.set('')
    _export_name.set('')
    _arguments.set(None)
    _approval_note.set(None)


def reset_gateway_tool_call() -> None:
    begin_gateway_tool_call()


def call_log_written() -> bool:
    return bool(_logged.get())


def snapshot_call_log_context() -> tuple:
    return (
        _logged.get(),
        _wrapper_tool.get(),
        _export_name.get(),
        _arguments.get(),
        _approval_note.get(),
    )


def restore_call_log_context(snapshot: tuple) -> tuple[contextvars.Token, ...]:
    logged, wrapper, export_name, arguments, note = snapshot
    return (
        _logged.set(logged),
        _wrapper_tool.set(wrapper),
        _export_name.set(export_name),
        _arguments.set(arguments),
        _approval_note.set(note),
    )


def reset_call_log_context(tokens: tuple[contextvars.Token, ...]) -> None:
    _approval_note.reset(tokens[4])
    _arguments.reset(tokens[3])
    _export_name.reset(tokens[2])
    _wrapper_tool.reset(tokens[1])
    _logged.reset(tokens[0])


def bind_wrapper_tool(name: str) -> contextvars.Token:
    return _wrapper_tool.set(str(name or '')[:64])


def reset_wrapper_tool(token: contextvars.Token) -> None:
    _wrapper_tool.reset(token)


def bind_export_name(name: str) -> contextvars.Token:
    return _export_name.set(str(name or '')[:255])


def reset_export_name(token: contextvars.Token) -> None:
    _export_name.reset(token)


def bind_call_arguments(arguments: dict | None) -> contextvars.Token:
    if isinstance(arguments, dict):
        return _arguments.set(arguments)
    return _arguments.set({})


def reset_call_arguments(token: contextvars.Token) -> None:
    _arguments.reset(token)


def note_approval(entry: dict) -> None:
    """Remember approval fields for the single execution row. Does not write."""
    if not isinstance(entry, dict):
        return
    _approval_note.set(
        {
            'approval_id': str(entry.get('approval_id') or '')[:64],
            'approval_channel': _channel(entry.get('approval_channel')),
            'approval_outcome': str(entry.get('approval_outcome') or '')[:32],
        }
    )


def public_status(*, outcome: str, status_code: int, error_code: str) -> str:
    """Map an internal audit outcome onto the admin status enum."""
    o = str(outcome or '').strip().lower()
    if o in {'pending_approval', 'pending', 'waiting_approval'}:
        return 'waiting_approval'
    if o == 'denied':
        return 'denied'
    if o in {'allowed', 'session_used'}:
        return 'allowed'
    code = str(error_code or '').strip().lower()
    http = int(status_code or 0)
    if code in _ERROR_TRANSPORT_CODES or http in {0, 408, 502, 503, 504}:
        return 'error'
    return 'failed'


def token_kind_from_claims(claims: dict | None) -> str:
    if not isinstance(claims, dict):
        return 'agent'
    if is_global_delegated_claims(claims):
        return 'delegated'
    if str(claims.get('personal_token_id') or '').strip():
        return 'personal'
    kind = str(claims.get('token_type') or claims.get('grant_type') or '').strip().lower()
    if kind and kind not in {'access', 'bearer'}:
        return kind[:32]
    return 'agent'


def service_for_log(service: str, tool_name: str) -> str:
    raw = str(service or '').strip().lower()[:32]
    if raw in SERVICES:
        return raw
    prefix = str(tool_name or '').split('_', 1)[0].strip().lower()
    if prefix in SERVICES:
        return prefix
    return raw or 'ai'


def redact_arguments_for_log(arguments: Any) -> dict:
    if not isinstance(arguments, dict):
        return {}
    redacted = redact_arguments(arguments)
    if not isinstance(redacted, dict):
        return {}
    try:
        encoded = json.dumps(redacted, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return {}
    if len(encoded) > 8000:
        return {'_truncated': True}
    return redacted


def safe_error_message(value: object) -> str:
    text = str(value or '').replace('\x00', ' ').strip()
    if not text:
        return ''
    text = _BEARER_RE.sub(r'\1***', text)
    text = _LONG_TOKEN_RE.sub('***', text)
    return text[:500]


def _channel(value: object) -> str:
    raw = str(value or '').strip().lower()
    return raw if raw in _CHANNELS else 'none'


def _user_id(claims: dict) -> int | None:
    raw = claims.get('user_id')
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value < 1:
        return None
    return value


def _first_text(*values: object, limit: int) -> str:
    for value in values:
        text = str(value or '').strip()
        if text:
            return text[:limit]
    return ''


def persist_mcp_call(entry: dict, *, arguments: dict | None = None) -> None:
    """Insert one row. A second call in the same tools/call is ignored. Never raises."""
    if _logged.get():
        return
    if not isinstance(entry, dict):
        return
    try:
        from apps.connector.models import McpCallLog

        claims = entry.get('agent_claims') if isinstance(entry.get('agent_claims'), dict) else {}
        note = _approval_note.get() if isinstance(_approval_note.get(), dict) else {}
        tool_name = _first_text(_export_name.get(), entry.get('tool_export_id'), entry.get('tool'), limit=255)
        wrapper = _first_text(entry.get('wrapper_tool'), _wrapper_tool.get(), limit=64)
        raw_arguments = arguments if isinstance(arguments, dict) else entry.get('arguments')
        if not isinstance(raw_arguments, dict):
            raw_arguments = _arguments.get()
        company = strict_numeric_company_id(entry.get('company_id'))
        if company is None:
            company = strict_numeric_company_id(claims.get('company_id'))
        if company is None:
            logger.warning('MCP call log skipped: missing company_id')
            return
        outcome = str(entry.get('outcome') or 'failed')
        status_code = int(entry.get('status') or 0)
        if status_code < 0:
            status_code = 0
        error_code = sanitize_error_code(entry.get('error_code')) or ''
        status = public_status(outcome=outcome, status_code=status_code, error_code=error_code)
        duration = entry.get('duration_ms')
        duration_ms = int(duration) if isinstance(duration, (int, float)) and duration >= 0 else 0
        McpCallLog.objects.create(
            company_id=int(company),
            agent_id=_first_text(entry.get('agent_id'), claims.get('agent_id'), limit=128),
            agent_name=_first_text(entry.get('agent_name'), claims.get('agent_name'), limit=200),
            client_id=_first_text(claims.get('client_id'), claims.get('azp'), entry.get('client_id'), limit=128),
            client_name=_first_text(entry.get('client_name'), limit=120),
            token_kind=token_kind_from_claims(claims)[:32],
            user_id=_user_id(claims),
            user_email=_first_text(claims.get('email'), entry.get('user_email'), limit=254),
            service=service_for_log(str(entry.get('service') or ''), tool_name),
            tool_name=tool_name,
            wrapper_tool=wrapper,
            arguments_redacted=redact_arguments_for_log(raw_arguments),
            status=status,
            status_code=status_code,
            error_code=error_code[:64],
            error_message=safe_error_message(entry.get('error_message')),
            duration_ms=duration_ms,
            approval_id=_first_text(entry.get('approval_id'), note.get('approval_id'), limit=64),
            approval_channel=_channel(entry.get('approval_channel') or note.get('approval_channel')),
            approval_outcome=_first_text(entry.get('approval_outcome'), note.get('approval_outcome'), limit=32),
        )
        _logged.set(True)
    except Exception:
        logger.warning('MCP call log write failed', exc_info=True)
