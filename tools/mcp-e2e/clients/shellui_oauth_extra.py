"""Apply Shellui protected-resource authorize hints (SaaS opt-in) to OAuth URLs."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunsplit

import requests

SHELLUI_MCP_AUTHORIZE_QUERY_KEY = 'shellui_mcp_authorize_query'


def fetch_authorize_query_params(mcp_url: str) -> dict[str, str]:
    parsed = urlparse(mcp_url)
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) < 3 or path_parts[0] != 'c' or path_parts[-1] != 'mcp':
        return {}
    company_id = path_parts[1]
    origin = f'{parsed.scheme}://{parsed.netloc}'
    meta_url = urljoin(origin, f'/.well-known/oauth-protected-resource/c/{company_id}/mcp')
    try:
        response = requests.get(meta_url, timeout=10)
    except requests.RequestException:
        return {}
    if response.status_code >= 400:
        return {}
    try:
        body = response.json()
    except ValueError:
        return {}
    ext = body.get(SHELLUI_MCP_AUTHORIZE_QUERY_KEY)
    if not isinstance(ext, dict):
        return {}
    return {str(k): str(v) for k, v in ext.items()}


def append_authorize_query_params(authorization_url: str, extra: dict[str, str]) -> str:
    if not extra:
        return authorization_url
    parts = urlparse(authorization_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key, value in extra.items():
        if key not in query:
            query[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def append_shellui_authorize_params(authorization_url: str, mcp_url: str) -> str:
    return append_authorize_query_params(authorization_url, fetch_authorize_query_params(mcp_url))
