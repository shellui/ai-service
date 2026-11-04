"""Identity revocation polling and MCP call log forwarding."""

from __future__ import annotations

import logging
import threading
from typing import Any

import requests
from django.conf import settings
from django.core.cache import cache

from shellui_django.mcp.internal import (
    REVOCATION_CACHE_SECONDS,
    InternalAssertionError,
    build_mcp_call_log_assertion,
    build_mcp_revocation_assertion,
    parse_trusted_revocation_poll_response,
)

logger = logging.getLogger(__name__)

_REVOKED_CACHE_KEY = 'mcp:revoked_trusted_payload'
_REVOKED_TRUST_KEY = 'mcp:revoked_list_trusted'
_REVOKED_LOCK = threading.Lock()


def _identity_origin() -> str:
    return (getattr(settings, 'IDENTITY_SERVICE_URL', '') or settings.IDENTITY_ISSUER or '').rstrip('/')


def _identity_audience(origin: str) -> str:
    """Identity checks internal assertions against its public issuer, not the internal URL we call."""
    return (settings.IDENTITY_ISSUER or origin).rstrip('/')


def _signing_kwargs() -> dict[str, str]:
    """Sign internal assertions with this service's own RS256 key; Identity trusts it via our JWKS."""
    signing = getattr(settings, 'AI_SERVICE_SIGNING_KEY', None)
    if signing is None or not settings.AI_SERVICE_ISSUER:
        raise InternalAssertionError('Service assertion signing is not configured.', status=503)
    return {'private_key_pem': signing.private_pem, 'kid': signing.kid, 'issuer': settings.AI_SERVICE_ISSUER}


def _revocation_headers(origin: str) -> dict[str, str]:
    assertion = build_mcp_revocation_assertion(audience_url=_identity_audience(origin), **_signing_kwargs())
    return {'Authorization': f'Bearer {assertion}'}


def _revocation_verify_kwargs(origin: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {'expected_issuer': settings.IDENTITY_ISSUER or origin}
    document = getattr(settings, 'IDENTITY_JWKS_DOCUMENT', None)
    if document is not None:
        kwargs['jwks'] = document
    else:
        jwks_url = getattr(settings, 'IDENTITY_JWKS_URL', None)
        if jwks_url:
            kwargs['identity_jwks_url'] = jwks_url
    return kwargs


def _mark_revocation_untrusted() -> None:
    cache.delete(_REVOKED_CACHE_KEY)
    cache.set(_REVOKED_TRUST_KEY, False, timeout=REVOCATION_CACHE_SECONDS)


def _store_trusted_revocation(*, revoked_ids: frozenset[str], agents: list[dict[str, Any]], cache_seconds: int) -> None:
    cache.set(
        _REVOKED_CACHE_KEY,
        {
            'revoked_ids': sorted(revoked_ids),
            'agents': agents,
            'cache_seconds': cache_seconds,
        },
        timeout=max(cache_seconds, REVOCATION_CACHE_SECONDS),
    )
    cache.set(_REVOKED_TRUST_KEY, True, timeout=max(cache_seconds, REVOCATION_CACHE_SECONDS))


def _cached_revocation() -> dict[str, Any] | None:
    if cache.get(_REVOKED_TRUST_KEY) is not True:
        return None
    raw = cache.get(_REVOKED_CACHE_KEY)
    if not isinstance(raw, dict):
        return None
    return raw


def _agent_blocked_for_tenant(agent_id: str, *, company_id: int | None, payload: dict[str, Any]) -> bool:
    revoked_ids = {str(item) for item in (payload.get('revoked_ids') or [])}
    if str(agent_id) not in revoked_ids:
        return False
    if company_id is None:
        return True
    agents = payload.get('agents') or []
    if not agents:
        return True
    for entry in agents:
        if str(entry.get('agent_id') or '') != str(agent_id):
            continue
        entry_company = entry.get('company_id')
        if entry_company is None:
            return True
        try:
            return int(entry_company) == int(company_id)
        except (TypeError, ValueError):
            return False
    return False


def _refresh_revocations() -> bool:
    origin = _identity_origin()
    if not origin:
        _mark_revocation_untrusted()
        return False
    url = f'{origin}/api/v1/mcp/internal/mcp-revocations'
    try:
        headers = _revocation_headers(origin)
    except InternalAssertionError:
        logger.warning('MCP revocation poll skipped: service assertion signing is not configured')
        _mark_revocation_untrusted()
        return False
    try:
        response = requests.get(url, headers=headers, timeout=5)
    except requests.RequestException as exc:
        logger.warning('MCP revocation poll failed: %s', type(exc).__name__)
        _mark_revocation_untrusted()
        return False
    if response.status_code >= 400:
        logger.warning('MCP revocation poll rejected: %s', response.status_code)
        _mark_revocation_untrusted()
        return False
    try:
        body = response.json()
    except ValueError:
        _mark_revocation_untrusted()
        return False
    try:
        revoked_ids, cache_seconds, agents = parse_trusted_revocation_poll_response(
            body,
            **_revocation_verify_kwargs(origin),
        )
    except Exception:
        _mark_revocation_untrusted()
        return False
    _store_trusted_revocation(revoked_ids=revoked_ids, agents=agents, cache_seconds=cache_seconds)
    return True


def agent_is_revoked(agent_id: str, company_id: int | None) -> bool:
    payload = _cached_revocation()
    if payload is None:
        with _REVOKED_LOCK:
            payload = _cached_revocation()
            if payload is None:
                if not _refresh_revocations():
                    return True
                payload = _cached_revocation()
    if payload is None:
        return True
    return _agent_blocked_for_tenant(agent_id, company_id=company_id, payload=payload)


def identity_revocation_unavailable() -> bool:
    if cache.get(_REVOKED_TRUST_KEY) is True:
        return False
    with _REVOKED_LOCK:
        if cache.get(_REVOKED_TRUST_KEY) is True:
            return False
        return not _refresh_revocations()


def personal_agent_bearer_valid(claims: dict) -> bool:
    """Personal agent JWTs must carry ``personal_token_id`` and ``jti``; OAuth agents pass through."""
    personal_token_id = str(claims.get('personal_token_id') or '').strip()
    if not personal_token_id:
        return True
    return bool(str(claims.get('jti') or '').strip())


def forward_call_log(entry: dict) -> None:
    origin = _identity_origin()
    if not origin:
        return
    url = f'{origin}/api/v1/mcp/internal/mcp-call-logs'
    try:
        assertion = build_mcp_call_log_assertion(audience_url=_identity_audience(origin), **_signing_kwargs())
    except InternalAssertionError:
        logger.warning('MCP call log skipped: service assertion signing is not configured')
        return
    body = {
        'agent_id': entry.get('agent_id'),
        'company_id': entry.get('company_id'),
        'service': entry.get('service') or 'ai',
        'tool': entry.get('tool') or '',
        'method': entry.get('method') or '',
        'path': entry.get('path') or '',
        'status': int(entry.get('status') or 0),
        'client_ip': str(entry.get('client_ip') or '')[:45],
        'result': str(entry.get('result') or '')[:32],
    }
    try:
        requests.post(
            url,
            json=body,
            headers={'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'},
            timeout=5,
        )
    except requests.RequestException as exc:
        logger.warning('MCP call log forward failed: %s', type(exc).__name__)
