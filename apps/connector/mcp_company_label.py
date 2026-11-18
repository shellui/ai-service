"""Resolve human-readable company labels for MCP tool copy."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests
from django.conf import settings
from django.core.cache import cache

from apps.connector.agent_record import AgentRecord
from apps.connector.downstream_tokens import DownstreamTokenError, mint_downstream_access_token
from apps.connector.mcp_tenant import agent_company_id, company_label_from_claims
from apps.connector.services import configured_service_urls, downstream_resource_for

logger = logging.getLogger(__name__)

_COMPANY_LABEL_CACHE_PREFIX = 'mcp:company_display_name:'
_FALLBACK_LABEL_RE = re.compile(r'^Company \d+$')


def _cache_seconds() -> int:
    return int(getattr(settings, 'MCP_COMPANY_LABEL_CACHE_SECONDS', 3600))


def _cached_label(company_id: int) -> str | None:
    raw = cache.get(f'{_COMPANY_LABEL_CACHE_PREFIX}{company_id}')
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def _store_label(company_id: int, name: str) -> None:
    cache.set(f'{_COMPANY_LABEL_CACHE_PREFIX}{company_id}', name, timeout=_cache_seconds())


def _parse_company_name_from_mcp_result(payload: dict[str, Any]) -> str | None:
    result = payload.get('result')
    if not isinstance(result, dict):
        return None
    content = result.get('content')
    if not isinstance(content, list):
        return None
    for block in content:
        if not isinstance(block, dict):
            continue
        text = str(block.get('text') or '').strip()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            name = data.get('name')
            if isinstance(name, str) and name.strip():
                return name.strip()
    return None


def fetch_company_name_from_identity(agent: AgentRecord, company_id: int) -> str | None:
    """Load company ``name`` via identity MCP ``get_companies`` (agent must allow identity)."""
    mcp_url = configured_service_urls().get('identity')
    if not mcp_url:
        return None
    resource = downstream_resource_for(mcp_url)
    if not resource:
        return None
    if 'identity' not in set(agent.services_allowed or []):
        return None
    try:
        token = mint_downstream_access_token(agent, resource=resource)
    except DownstreamTokenError as exc:
        logger.debug('Company label identity token mint failed: %s', exc)
        return None
    timeout = float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 5))
    body = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'tools/call',
        'params': {
            'name': 'get_companies',
            'arguments': {'path_params': {'pk': str(company_id)}},
        },
    }
    try:
        response = requests.post(
            mcp_url,
            json=body,
            headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug('Company label identity MCP call failed: %s', type(exc).__name__)
        return None
    if payload.get('error'):
        return None
    return _parse_company_name_from_mcp_result(payload)


def resolve_company_label(
    claims: dict[str, Any],
    *,
    agent: AgentRecord | None = None,
) -> str:
    """Display name for tool titles; falls back to identity lookup when the token has only ``company_id``."""
    label = company_label_from_claims(claims)
    if not _FALLBACK_LABEL_RE.match(label):
        return label
    try:
        company_id = agent_company_id(claims)
    except Exception:
        return label
    cached = _cached_label(company_id)
    if cached:
        return cached
    if agent is not None and int(agent.company_id) == int(company_id):
        fetched = fetch_company_name_from_identity(agent, company_id)
        if fetched:
            _store_label(company_id, fetched)
            return fetched
    return label
