"""Identity revocation polling and MCP call log forwarding."""

from __future__ import annotations

import hashlib
import json
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
    verify_mcp_revocation_list_response,
)

from apps.connector.mcp_audit_codes import ALLOWED_ERROR_CODES
from apps.connector.mcp_call_audit import OUTCOMES, legacy_result_token, safe_route_path_for_audit
from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_revocation import revocation_fingerprint_material

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


def verify_mcp_revocation_list_response_identity135(
    payload: dict[str, Any],
    *,
    expected_issuer: str,
    identity_jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    jwks_timeout: float = 10.0,
) -> dict[str, Any]:
    """Trusted revocation poll (commons #14 / identity #135): signed JWT + body, validated agent rows."""
    return verify_mcp_revocation_list_response(
        payload,
        expected_issuer=expected_issuer,
        identity_jwks_url=identity_jwks_url,
        jwks=jwks,
        jwks_timeout=jwks_timeout,
    )


def parse_trusted_revocation_poll_response_identity135(
    payload: dict[str, Any],
    *,
    expected_issuer: str,
    identity_jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    jwks_timeout: float = 10.0,
) -> tuple[frozenset[str], int, list[dict[str, Any]], int | None]:
    """Compatibility name: returns policy version as int when present (commons #14)."""
    trusted = verify_mcp_revocation_list_response(
        payload,
        expected_issuer=expected_issuer,
        identity_jwks_url=identity_jwks_url,
        jwks=jwks,
        jwks_timeout=jwks_timeout,
    )
    ids = frozenset(str(x) for x in (trusted.get('revoked_agent_ids') or []))
    cache_seconds = int(trusted.get('cache_seconds') or REVOCATION_CACHE_SECONDS)
    agents = list(trusted.get('agents') or [])
    policy = trusted.get('revocation_policy_version')
    policy_i = int(policy) if policy is not None else None
    return ids, cache_seconds, agents, policy_i


def _mark_revocation_untrusted() -> None:
    cache.delete(_REVOKED_CACHE_KEY)
    cache.set(_REVOKED_TRUST_KEY, False, timeout=REVOCATION_CACHE_SECONDS)


def _store_trusted_revocation(
    *,
    revoked_ids: frozenset[str],
    agents: list[dict[str, Any]],
    cache_seconds: int,
    revocation_policy_version: int | None,
    max_active_grant_version: int | None,
) -> None:
    cache.set(
        _REVOKED_CACHE_KEY,
        {
            'revoked_ids': sorted(revoked_ids),
            'agents': agents,
            'cache_seconds': cache_seconds,
            'revocation_policy_version': revocation_policy_version,
            'max_active_grant_version': max_active_grant_version,
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
        parsed = strict_numeric_company_id(entry_company)
        if parsed is None:
            # Fail closed: non-numeric / UUID-shaped company_id cannot be matched to regional int scope.
            return True
        return parsed == int(company_id)
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
        trusted = verify_mcp_revocation_list_response(
            body,
            **_revocation_verify_kwargs(origin),
        )
    except Exception:
        _mark_revocation_untrusted()
        return False
    revoked_ids = frozenset(str(x) for x in (trusted.get('revoked_agent_ids') or []))
    cache_seconds = int(trusted.get('cache_seconds') or REVOCATION_CACHE_SECONDS)
    agents = list(trusted.get('agents') or [])
    policy_ver = trusted.get('revocation_policy_version')
    policy_i = int(policy_ver) if policy_ver is not None else None
    max_gv = trusted.get('max_active_grant_version')
    max_gv_i = int(max_gv) if max_gv is not None else None
    _store_trusted_revocation(
        revoked_ids=revoked_ids,
        agents=agents,
        cache_seconds=cache_seconds,
        revocation_policy_version=policy_i,
        max_active_grant_version=max_gv_i,
    )
    return True


def revocation_list_fingerprint() -> str | None:
    """Stable hash of the trusted revocation snapshot; None when list is unavailable."""
    payload = _cached_revocation()
    if payload is None:
        return None
    raw = revocation_fingerprint_material(payload)
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


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


_OUTCOMES = frozenset({'allowed', 'failed', 'denied', 'pending', 'session_used'})
_ACCESS_KINDS = frozenset({'read', 'write', 'destructive'})
_RESULT_WHITELIST = frozenset({'success', 'error', 'denied', 'pending'})


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
    outcome_raw = str(entry.get('outcome') or '').strip().lower()
    if outcome_raw == 'pending':
        outcome = 'pending_approval'
    elif outcome_raw in _OUTCOMES:
        outcome = outcome_raw
    else:
        outcome = ''
    access_raw = str(entry.get('access_kind') or entry.get('access_level') or '').strip().lower()
    access_kind = access_raw if access_raw in _ACCESS_KINDS else ''
    op_title = str(entry.get('operation_title') or '').strip()[:200]
    resource_label = str(entry.get('resource_label') or '').strip()[:200]
    tool_export_id = str(entry.get('tool_export_id') or entry.get('tool') or '')[:256]
    body: dict[str, Any] = {
        'agent_id': entry.get('agent_id'),
        'company_id': entry.get('company_id'),
        'service': str(entry.get('service') or 'ai')[:64],
        'tool': str(entry.get('tool') or '')[:256],
        'tool_export_id': tool_export_id,
        'method': str(entry.get('method') or '')[:16],
        'path': safe_route_path_for_audit(entry.get('path'))[:512],
        'status': int(entry.get('status') or 0),
        'client_ip': str(entry.get('client_ip') or '')[:45],
    }
    res_raw = str(entry.get('result') or '').strip()[:32]
    if res_raw in _RESULT_WHITELIST:
        body['result'] = res_raw
    else:
        oa = outcome_raw if outcome_raw in OUTCOMES else 'failed'
        body['result'] = legacy_result_token(outcome=oa)[:32]
    if outcome:
        body['outcome'] = outcome
    if access_kind:
        body['access_kind'] = access_kind
    ro = entry.get('read_only_hint')
    if isinstance(ro, bool):
        body['read_only_hint'] = ro
    dh = entry.get('destructive_hint')
    if isinstance(dh, bool):
        body['destructive_hint'] = dh
    if op_title:
        body['operation_title'] = op_title
    if resource_label:
        body['resource_label'] = resource_label
    cn = str(entry.get('company_name') or '').strip()[:200]
    if cn:
        body['company_name'] = cn
    an = str(entry.get('agent_name') or '').strip()[:200]
    if an:
        body['agent_name'] = an
    aid = str(entry.get('approval_id') or entry.get('approval_request_id') or '').strip()[:64]
    if aid:
        body['approval_id'] = aid
    duration = entry.get('duration_ms')
    if isinstance(duration, (int, float)) and duration >= 0:
        body['duration_ms'] = int(duration)
    ec_raw = entry.get('error_code')
    if isinstance(ec_raw, str):
        ec = ec_raw.strip().lower()[:64]
        if ec in ALLOWED_ERROR_CODES:
            body['error_code'] = ec
    try:
        requests.post(
            url,
            json=body,
            headers={'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'},
            timeout=5,
        )
    except requests.RequestException as exc:
        logger.warning('MCP call log forward failed: %s', type(exc).__name__)
