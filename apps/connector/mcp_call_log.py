"""Shape MCP call log rows forwarded to identity (no arguments or secrets)."""

from __future__ import annotations

import contextvars
import time

from django.http import HttpRequest

_mcp_tool_call_started_at: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    'mcp_tool_call_started_at',
    default=None,
)


def begin_mcp_tool_call_timer() -> contextvars.Token:
    return _mcp_tool_call_started_at.set(time.monotonic())


def reset_mcp_tool_call_timer(token: contextvars.Token) -> None:
    _mcp_tool_call_started_at.reset(token)


def mcp_tool_call_duration_ms() -> int | None:
    started = _mcp_tool_call_started_at.get()
    if started is None:
        return None
    return max(0, int((time.monotonic() - started) * 1000))


def apply_duration_ms(entry: dict) -> None:
    if isinstance(entry.get('duration_ms'), (int, float)):
        entry['duration_ms'] = max(0, int(entry['duration_ms']))
        return
    elapsed = mcp_tool_call_duration_ms()
    if elapsed is not None:
        entry['duration_ms'] = elapsed


def client_ip_from_request(request: HttpRequest | None) -> str:
    if request is None:
        return ''
    forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
    if forwarded:
        return forwarded[:45]
    remote = (request.META.get('REMOTE_ADDR') or '').strip()
    return remote[:45]


def mcp_call_result(
    *,
    status_code: int | None,
    is_error: bool | None = None,
    log_result: str | None = None,
) -> str:
    if log_result:
        return str(log_result)[:32]
    if is_error is True:
        return 'error'
    if is_error is False:
        return 'success'
    code = int(status_code or 0)
    if code <= 0:
        return 'error'
    return 'success' if 200 <= code < 400 else 'error'
