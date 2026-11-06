"""Allowlisted audit fields for identity personal activity (no raw provider text)."""

from __future__ import annotations

# Small stable set only; anything else is dropped (fail closed for UI).
ALLOWED_ERROR_CODES = frozenset(
    {
        'bad_request',
        'unauthorized',
        'forbidden',
        'not_found',
        'conflict',
        'rate_limited',
        'timeout',
        'upstream_error',
        'internal_error',
        'denied',
        'expired',
        'out_of_sync',
        'mcp_tool_error',
    },
)


def sanitize_error_code(raw: object) -> str | None:
    code = str(raw or '').strip().lower()[:64]
    return code if code in ALLOWED_ERROR_CODES else None


def error_code_from_http(*, status: int, is_error: bool | None) -> str | None:
    """Map HTTP status to a single allowlisted code (no raw bodies)."""
    code = int(status or 0)
    if is_error is not True and 200 <= code < 400:
        return None
    if code == 400:
        return 'bad_request'
    if code in {401, 407}:
        return 'unauthorized'
    if code == 403:
        return 'forbidden'
    if code == 404:
        return 'not_found'
    if code == 409:
        return 'conflict'
    if code == 429:
        return 'rate_limited'
    if code == 408 or code == 504:
        return 'timeout'
    if 500 <= code < 600:
        return 'upstream_error' if code >= 502 else 'internal_error'
    return 'internal_error'
