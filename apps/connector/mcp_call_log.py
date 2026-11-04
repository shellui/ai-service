"""Shape MCP call log rows forwarded to identity (no arguments or secrets)."""

from __future__ import annotations

from django.http import HttpRequest


def client_ip_from_request(request: HttpRequest | None) -> str:
    if request is None:
        return ''
    forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
    if forwarded:
        return forwarded[:45]
    remote = (request.META.get('REMOTE_ADDR') or '').strip()
    return remote[:45]


def mcp_call_result(*, status_code: int | None, is_error: bool | None = None) -> str:
    if is_error is True:
        return 'error'
    if is_error is False:
        return 'success'
    code = int(status_code or 0)
    if code <= 0:
        return 'error'
    return 'success' if 200 <= code < 400 else 'error'
