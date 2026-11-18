"""Redirect URI validation for MCP OAuth. Ported from saas-service."""

from __future__ import annotations

import unicodedata
from urllib.parse import urlsplit

from django.conf import settings
from django.http import HttpRequest

MAX_MCP_REDIRECT_URIS = 16

_UNSAFE_SCHEMES = frozenset({'javascript', 'data', 'vbscript', 'file', 'blob', 'about'})
_LOOPBACK_HOSTS = frozenset({'localhost', '127.0.0.1', '::1'})


def _loopback_allowed() -> bool:
    return bool(getattr(settings, 'OAUTH_ALLOW_LOOPBACK_REDIRECTS', settings.DEBUG))


def _is_ignorable(char: str) -> bool:
    return char.isspace() or unicodedata.category(char) in {'Cc', 'Cf'}


def _strip_whitespace_and_controls(value: str) -> str:
    return ''.join(char for char in value if not _is_ignorable(char))


def _is_loopback(parts) -> bool:
    host = (parts.hostname or '').lower()
    if host in _LOOPBACK_HOSTS:
        return True
    netloc = (parts.netloc or '').lower()
    return netloc == '[::1]' or netloc.startswith('[::1]:')


def validate_mcp_redirect_uri(request: HttpRequest, raw: str) -> tuple[str | None, str | None]:
    uri = _strip_whitespace_and_controls(raw or '')
    if not uri:
        return None, 'redirect_uri is required.'
    parts = urlsplit(uri)
    scheme = (parts.scheme or '').lower()
    if scheme in _UNSAFE_SCHEMES:
        return None, 'redirect_uri is invalid.'
    if not scheme or not parts.netloc:
        return None, 'redirect_uri must be absolute.'
    if scheme in {'http', 'https'}:
        if _is_loopback(parts):
            if not _loopback_allowed():
                return None, 'Loopback redirect URIs are not allowed.'
            return uri, None
        if scheme == 'http':
            return None, 'http redirect URIs are only allowed for loopback hosts.'
        return uri, None
    if parts.netloc:
        return uri, None
    return None, 'redirect_uri is invalid.'


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
