"""REST calls to saas-service. saas keeps no MCP code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
from django.conf import settings

from apps.global_mcp.resources import saas_base


class SaasError(Exception):
    def __init__(self, status: int, body: Any, message: str = '') -> None:
        super().__init__(message or f'saas HTTP {status}')
        self.status = status
        self.body = body


@dataclass
class MeProfile:
    sub: str
    email: str
    name: str
    raw: dict


def _timeout() -> float:
    return float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 5) or 5)


def request_json(
    method: str,
    path: str,
    *,
    token: str,
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
) -> tuple[int, Any]:
    base = saas_base()
    if not base:
        raise SaasError(0, None, 'SAAS_SERVICE_URL is not set.')
    url = urljoin(base + '/', path.lstrip('/'))
    hdrs = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
    if headers:
        hdrs.update(headers)
    response = requests.request(
        method.upper(),
        url,
        params=query or None,
        json=body if body is not None else None,
        headers=hdrs,
        timeout=_timeout(),
    )
    try:
        payload = response.json()
    except ValueError:
        payload = {'detail': response.text[:500]}
    return response.status_code, payload


def fetch_me(access_token: str) -> MeProfile | None:
    """Return the Shellui account, or None when saas does not know this user."""
    try:
        status, payload = request_json('GET', '/api/v1/me', token=access_token)
    except requests.RequestException:
        return None
    if status in {401, 403, 404} or not isinstance(payload, dict):
        return None
    if status >= 400:
        return None
    sub = str(payload.get('sub') or payload.get('id') or '').strip()
    email = str(payload.get('email') or '').strip()
    if not sub or not email:
        return None
    name = str(payload.get('name') or payload.get('display_name') or '').strip()
    return MeProfile(sub=sub, email=email, name=name, raw=payload)
