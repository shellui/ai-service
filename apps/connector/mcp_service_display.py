"""Shellui MCP service display names (no Django imports; safe for e2e clients)."""

from __future__ import annotations

MCP_SERVICE_DISPLAY_NAMES: dict[str, str] = {
    'ai': 'AI',
    'identity': 'Identity',
    'storage': 'Storage',
    'hosting': 'Hosting',
    'email': 'Email',
    'saas': 'SaaS',
}


def mcp_service_display_name(service_id: str) -> str:
    key = str(service_id or '').strip().lower()
    return MCP_SERVICE_DISPLAY_NAMES.get(key, key.capitalize() if key else 'Shellui')
