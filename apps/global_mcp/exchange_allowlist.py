"""Hosts that may receive a regional subject token or a regional access token."""

from __future__ import annotations

from urllib.parse import urlsplit

from django.conf import settings


class ExchangeHostRejected(Exception):
    """The company record named a host this process will not call."""

    def __init__(self, message: str = 'Region URL is not an allowed exchange host.') -> None:
        super().__init__(message)


def allowed_entries() -> list[str]:
    raw = getattr(settings, 'REGIONAL_EXCHANGE_ALLOWED_HOSTS', ()) or ()
    if isinstance(raw, str):
        items = raw.split(',')
    else:
        items = list(raw)
    entries: list[str] = []
    for item in items:
        text = str(item).strip().lower()
        if not text or '://' in text or '/' in text or any(char.isspace() for char in text):
            continue
        entries.append(text)
    return entries


def exchange_url_allowed(url: str) -> bool:
    text = str(url or '').strip()
    if not text or any(char in text for char in '\r\n\t\\ '):
        return False
    parts = urlsplit(text)
    if parts.username or parts.password or parts.fragment or parts.query:
        return False
    scheme = (parts.scheme or '').lower()
    if scheme not in {'http', 'https'}:
        return False
    if not getattr(settings, 'DEBUG', False) and scheme != 'https':
        return False
    host = _normalize_host(parts.hostname or '')
    if not host or not _host_allowed(host, parts.port, scheme):
        return False
    return True


def require_exchange_url(url: str) -> str:
    cleaned = str(url or '').strip()
    if not exchange_url_allowed(cleaned):
        raise ExchangeHostRejected()
    return cleaned


def _host_allowed(host: str, port: int | None, scheme: str) -> bool:
    for entry in allowed_entries():
        kind, value, entry_port = _parse_entry(entry)
        if not value:
            continue
        if kind == 'suffix':
            if host == value or host.endswith('.' + value):
                return True
            continue
        if host == value and _port_matches(entry_port, port, scheme):
            return True
    return False


def _parse_entry(entry: str) -> tuple[str, str, int | None]:
    if entry.startswith('*.'):
        return 'suffix', _normalize_host(entry[2:]), None
    if entry.startswith('.'):
        return 'suffix', _normalize_host(entry[1:]), None
    host, port = _split_host_port(entry)
    return 'host', _normalize_host(host), port


def _split_host_port(entry: str) -> tuple[str, int | None]:
    if entry.startswith('['):
        end = entry.find(']')
        if end == -1:
            return entry, None
        host = entry[1:end]
        rest = entry[end + 1 :]
        if rest.startswith(':') and rest[1:].isdigit():
            return host, int(rest[1:])
        if rest:
            return '', None
        return host, None
    if entry.count(':') == 1:
        host, _, raw_port = entry.partition(':')
        if raw_port.isdigit():
            return host, int(raw_port)
    return entry, None


def _normalize_host(host: str) -> str:
    text = str(host or '').strip().lower().rstrip('.')
    if not text:
        return ''
    if any(ord(char) > 127 for char in text):
        try:
            return text.encode('idna').decode('ascii')
        except UnicodeError:
            return ''
    return text


def _default_port(scheme: str) -> int:
    return 443 if scheme == 'https' else 80


def _port_matches(expected: int | None, actual: int | None, scheme: str) -> bool:
    actual_port = _default_port(scheme) if actual is None else actual
    expected_port = _default_port(scheme) if expected is None else expected
    return actual_port == expected_port
