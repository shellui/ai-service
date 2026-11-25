"""Redirect URI validation for global MCP OAuth.

Rules, aligned with identity-service ``apps/agents/oauth_redirect.py`` for loopback:
- https on any host, or http on a loopback host (127.0.0.1, localhost, ::1) on any port.
  Loopback is always allowed (RFC 8252 native and CLI clients). There is no toggle.
- a private-use app scheme with a host (for example ``cursor://...``) stays allowed;
- no javascript:, data:, file: and similar schemes;
- no fragment and no user info;
- authorize and token compare the value to the registered list exactly.
"""

from __future__ import annotations

import unicodedata
from urllib.parse import urlsplit

from django.http import HttpRequest

MAX_MCP_REDIRECT_URIS = 16
MAX_MCP_REDIRECT_URI_LENGTH = 500

_UNSAFE_SCHEMES = frozenset({'javascript', 'data', 'vbscript', 'file', 'blob', 'about'})
_LOOPBACK_HOSTS = frozenset({'localhost', '127.0.0.1', '::1'})


def _is_ignorable(char: str) -> bool:
    return char.isspace() or unicodedata.category(char) in {'Cc', 'Cf'}


def _strip_whitespace_and_controls(value: str) -> str:
    return ''.join(char for char in value if not _is_ignorable(char))


def _is_loopback(parts) -> bool:
    return (parts.hostname or '').lower() in _LOOPBACK_HOSTS


def validate_mcp_redirect_uri(request: HttpRequest | None, raw: str) -> tuple[str | None, str | None]:
    del request
    uri = _strip_whitespace_and_controls(raw or '')
    if not uri:
        return None, 'redirect_uri is required.'
    if len(uri) > MAX_MCP_REDIRECT_URI_LENGTH:
        return None, 'redirect_uri is too long.'
    if '#' in uri:
        return None, 'redirect_uri must not include a fragment.'
    try:
        parts = urlsplit(uri)
        parts.port
    except ValueError:
        return None, 'redirect_uri is invalid.'
    scheme = (parts.scheme or '').lower()
    if scheme in _UNSAFE_SCHEMES:
        return None, 'redirect_uri is invalid.'
    if not scheme or not parts.netloc:
        return None, 'redirect_uri must be absolute.'
    if parts.username is not None or parts.password is not None or '@' in parts.netloc:
        return None, 'redirect_uri is invalid.'
    if scheme == 'http' and not _is_loopback(parts):
        return None, 'http redirect URIs are only allowed for loopback hosts.'
    return uri, None


def normalize_mcp_redirect_uris(request: HttpRequest, uris: list) -> tuple[list[str] | None, str | None]:
    if not isinstance(uris, list) or not uris:
        return None, 'invalid_redirect_uris'
    if len(uris) > MAX_MCP_REDIRECT_URIS:
        return None, 'too_many_redirect_uris'
    normalized: list[str] = []
    for item in uris:
        canonical, err = validate_mcp_redirect_uri(request, _strip_whitespace_and_controls(str(item)))
        if err or not canonical:
            return None, 'invalid_redirect_uris'
        if canonical not in normalized:
            normalized.append(canonical)
    return normalized, None
