"""Per-company MCP gateway URLs: ``{AI_PUBLIC_URL}/c/<company_id>/mcp``."""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest
import hmac
import ipaddress
import re
from urllib.parse import urlsplit

_COMPANY_PATH = re.compile(r'^/c/[1-9][0-9]{0,18}/mcp$')
_LOOPBACK_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1'})
_CGNAT_SHARED = ipaddress.ip_network('100.64.0.0/10')
PLAIN_MCP_MESSAGE = 'Connect to the per-company MCP URL: /c/<company_id>/mcp.'


def _http_dev_host_allowed(host: str | None) -> bool:
    """Loopback names/IPs and private/CGNAT IP literals (LAN / Tailscale)."""
    h = (host or '').lower()
    if h in _LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip in _CGNAT_SHARED
    )


def normalize_company_resource(raw: str | None) -> str | None:
    """Canonical ``https://host/c/<company_id>/mcp`` (http on loopback/private IPs). None otherwise."""
    s = str(raw or '').strip()
    if not s or '#' in s or '?' in s:
        return None
    s = s.rstrip('/')
    try:
        parsed = urlsplit(s)
    except ValueError:
        return None
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password:
        return None
    if not _COMPANY_PATH.match(parsed.path):
        return None
    if parsed.scheme == 'http' and not _http_dev_host_allowed(parsed.hostname):
        return None
    return s


def company_audience_matches(claims: dict, expected_resource: str) -> bool:
    expected = normalize_company_resource(expected_resource) or ''
    presented = normalize_company_resource(str(claims.get('aud') or '')) or ''
    return bool(expected and presented) and hmac.compare_digest(expected, presented)


def public_origin(request: HttpRequest) -> str:
    configured = str(getattr(settings, 'AI_PUBLIC_URL', '') or '').strip().rstrip('/')
    if configured:
        return configured
    # Without a configured origin, fall back to the request (local tests only).
    return request.build_absolute_uri('/').rstrip('/')


def company_mcp_resource(request: HttpRequest, company_id: int) -> str:
    return normalize_company_resource(f'{public_origin(request)}/c/{int(company_id)}/mcp') or ''


def company_id_from_resource(resource: str | None) -> int | None:
    """Parse ``company_id`` from a canonical per-company MCP resource URL."""
    url = normalize_company_resource(resource)
    if not url:
        return None
    parts = urlsplit(url).path.strip('/').split('/')
    if len(parts) != 3 or parts[0] != 'c' or parts[2] != 'mcp':
        return None
    try:
        company_id = int(parts[1])
    except ValueError:
        return None
    return company_id if company_id >= 1 else None


def company_metadata_url(request: HttpRequest, company_id: int) -> str:
    return f'{public_origin(request)}/.well-known/oauth-protected-resource/c/{int(company_id)}/mcp'


def mcp_www_authenticate(request: HttpRequest, company_id: int) -> str:
    """RFC 9728 challenge. ``resource_metadata`` is the path-inserted protected-resource URL."""
    metadata = company_metadata_url(request, company_id)
    return f'Bearer realm="mcp", resource_metadata="{metadata}", scope="mcp"'
