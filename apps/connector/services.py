"""MCP service discovery from configured origins only (SSRF-safe)."""

from __future__ import annotations

from django.conf import settings


def _origin(url: str) -> str:
    return str(url or '').strip().rstrip('/')


def list_mcp_services() -> list[dict[str, str]]:
    """Return MCP base URLs for connected Shellui services."""
    items: list[dict[str, str]] = []
    identity = _origin(getattr(settings, 'IDENTITY_SERVICE_URL', '') or getattr(settings, 'IDENTITY_ISSUER', ''))
    if identity:
        items.append({'id': 'identity', 'name': 'Identity', 'mcp_url': f'{identity}/mcp'})
    storage = _origin(getattr(settings, 'STORAGE_SERVICE_URL', ''))
    if storage:
        items.append({'id': 'storage', 'name': 'Storage', 'mcp_url': f'{storage}/mcp'})
    hosting = _origin(getattr(settings, 'HOSTING_SERVICE_URL', ''))
    if hosting:
        items.append({'id': 'hosting', 'name': 'Hosting', 'mcp_url': f'{hosting}/mcp'})
    email = _origin(getattr(settings, 'EMAIL_SERVICE_URL', ''))
    if email and getattr(settings, 'EMAIL_SERVICE_API_KEY', ''):
        items.append({'id': 'email', 'name': 'Email', 'mcp_url': f'{email}/mcp'})
    saas = _origin(getattr(settings, 'SAAS_SERVICE_URL', ''))
    if saas:
        items.append({'id': 'saas', 'name': 'SaaS', 'mcp_url': f'{saas}/mcp'})
    return items


def configured_service_urls() -> dict[str, str]:
    return {str(item['id']): str(item['mcp_url']) for item in list_mcp_services()}
