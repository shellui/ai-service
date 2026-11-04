"""MCP service discovery from configured origins only (SSRF-safe)."""

from __future__ import annotations

from django.conf import settings


def _origin(url: str) -> str:
    return str(url or '').strip().rstrip('/')


def _item(service_id: str, name: str, origin: str, public_origin: str) -> dict[str, str]:
    # mcp_url is where this service calls; resource is the public URL identity binds tokens to.
    return {
        'id': service_id,
        'name': name,
        'mcp_url': f'{origin}/mcp',
        'resource': f'{_origin(public_origin) or origin}/mcp',
    }


def list_mcp_services() -> list[dict[str, str]]:
    """Return MCP base URLs for connected Shellui services."""
    items: list[dict[str, str]] = []
    identity = _origin(getattr(settings, 'IDENTITY_SERVICE_URL', '') or getattr(settings, 'IDENTITY_ISSUER', ''))
    if identity:
        items.append(_item('identity', 'Identity', identity, getattr(settings, 'IDENTITY_ISSUER', '') or ''))
    storage = _origin(getattr(settings, 'STORAGE_SERVICE_URL', ''))
    if storage:
        items.append(_item('storage', 'Storage', storage, getattr(settings, 'STORAGE_SERVICE_PUBLIC_URL', '') or ''))
    hosting = _origin(getattr(settings, 'HOSTING_SERVICE_URL', ''))
    if hosting:
        items.append(_item('hosting', 'Hosting', hosting, getattr(settings, 'HOSTING_SERVICE_PUBLIC_URL', '') or ''))
    email = _origin(getattr(settings, 'EMAIL_SERVICE_URL', ''))
    if email and getattr(settings, 'EMAIL_SERVICE_API_KEY', ''):
        items.append(_item('email', 'Email', email, getattr(settings, 'EMAIL_SERVICE_PUBLIC_URL', '') or ''))
    saas = _origin(getattr(settings, 'SAAS_SERVICE_URL', ''))
    if saas:
        items.append(_item('saas', 'SaaS', saas, getattr(settings, 'SAAS_SERVICE_PUBLIC_URL', '') or ''))
    return items


def configured_service_urls() -> dict[str, str]:
    return {str(item['id']): str(item['mcp_url']) for item in list_mcp_services()}


def downstream_resource_for(mcp_url: str) -> str | None:
    """Public resource for a configured downstream ``mcp_url``. None when the URL is not configured."""
    target = _origin(mcp_url)
    for item in list_mcp_services():
        if _origin(item['mcp_url']) == target:
            return item['resource']
    return None
