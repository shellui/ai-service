"""Shellui MCP OAuth authorize URL hints (e.g. SaaS opt-in at identity consent)."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.conf import settings

# When ai-service forwards SaaS tools, identity consent may offer optional SaaS access.
SHELLUI_MCP_AUTHORIZE_QUERY_KEY = 'shellui_mcp_authorize_query'
SAAS_OFFERED_PARAM = 'saas_offered'
SAAS_OFFERED_VALUE = '1'


def saas_tools_forwarded() -> bool:
    """True when this gateway exposes downstream SaaS MCP tools."""
    return bool(str(getattr(settings, 'SAAS_SERVICE_URL', '') or '').strip())


def mcp_authorize_query_params() -> dict[str, str]:
    """Extra query parameters for ``GET /oauth/mcp/authorize`` when SaaS is in catalog."""
    if not saas_tools_forwarded():
        return {}
    return {SAAS_OFFERED_PARAM: SAAS_OFFERED_VALUE}


def protected_resource_authorize_extensions() -> dict[str, dict[str, str]]:
    """Optional RFC 9728 metadata extensions for MCP OAuth clients."""
    params = mcp_authorize_query_params()
    if not params:
        return {}
    return {SHELLUI_MCP_AUTHORIZE_QUERY_KEY: dict(params)}


def append_authorize_query_params(authorization_url: str, extra: dict[str, str] | None = None) -> str:
    """Merge ``extra`` (and SaaS opt-in when configured) into an authorization URL."""
    merged = dict(mcp_authorize_query_params())
    if extra:
        merged.update({str(k): str(v) for k, v in extra.items()})
    if not merged:
        return authorization_url
    parts = urlsplit(authorization_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key, value in merged.items():
        if key not in query:
            query[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
