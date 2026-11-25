"""Public URLs for the global MCP resource."""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest


def issuer() -> str:
    return str(getattr(settings, 'AI_SERVICE_ISSUER', '') or '').rstrip('/')


def public_origin(request: HttpRequest | None = None) -> str:
    configured = str(getattr(settings, 'AI_PUBLIC_URL', '') or '').strip().rstrip('/')
    if configured:
        return configured
    if request is not None:
        return request.build_absolute_uri('/').rstrip('/')
    return issuer()


def mcp_resource(request: HttpRequest | None = None) -> str:
    return f'{public_origin(request)}/mcp'


def saas_base() -> str:
    internal = str(getattr(settings, 'SAAS_SERVICE_INTERNAL_URL', '') or '').rstrip('/')
    public = str(getattr(settings, 'SAAS_SERVICE_URL', '') or '').rstrip('/')
    return internal or public


def saas_audience() -> str:
    explicit = str(getattr(settings, 'SAAS_API_AUDIENCE', '') or '').rstrip('/')
    if explicit:
        return explicit
    public = str(getattr(settings, 'SAAS_SERVICE_URL', '') or '').rstrip('/')
    return f'{public}/api' if public else ''


def region_internal(url: str) -> str:
    """Same URL on the internal origin when GLOBAL_REGION_INTERNAL_URLS maps its public origin."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    origin = f'{parts.scheme}://{parts.netloc}'
    internal = (getattr(settings, 'GLOBAL_REGION_INTERNAL_URLS', None) or {}).get(origin)
    return internal + url[len(origin):] if internal else url
