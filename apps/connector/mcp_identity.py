"""Identity revocation polling and delegated-authority checks.

Tool-call logs are stored in ai-service (``McpCallLog``). This module does not
forward them to identity ingest.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

import jwt
import requests
from django.conf import settings

# Patchable indirection for tests (avoid mocking ``requests.post`` globally).
_http_post = requests.post
from django.core.cache import cache
from shellui_django.mcp.internal import (
    REVOCATION_CACHE_SECONDS,
    InternalAssertionError,
    build_mcp_revocation_assertion,
    verify_mcp_revocation_list_response,
)

from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_revocation import revocation_fingerprint_material
from apps.connector.mcp_setup_context import (
    global_binding_triplet_from_claims,
    is_global_delegated_claims,
    parse_global_company_id,
    parse_int_version_claim,
)

logger = logging.getLogger(__name__)

# Identity canonical live delegated-agent binding (identity PR #135+); do not use alternate URL spellings.
DELEGATED_AGENT_AUTHORITY_PATH = '/api/v1/mcp/internal/mcp-agent-delegated-authority'
DELEGATED_AGENT_AUTHORITY_AUDIENCE = 'shellui-mcp-agent-delegated-authority'
DELEGATED_AGENT_AUTHORITY_SCOPE = 'mcp.agent.delegated.authority.read'
DELEGATED_AGENT_AUTHORITY_ASSERTION_TTL_SECONDS = 60

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


def _build_delegated_agent_authority_assertion(*, audience_url: str) -> str:
    """RS256 internal assertion for ``POST .../mcp-agent-delegated-authority`` (Identity #135+)."""
    signing = _signing_kwargs()
    now = int(time.time())
    ttl = min(DELEGATED_AGENT_AUTHORITY_ASSERTION_TTL_SECONDS, 60)
    claims: dict[str, Any] = {
        'iss': str(signing['issuer']).strip().rstrip('/'),
        'aud': DELEGATED_AGENT_AUTHORITY_AUDIENCE,
        'sub': 'service',
        'scope': DELEGATED_AGENT_AUTHORITY_SCOPE,
        'target': audience_url,
        'iat': now,
        'exp': now + ttl,
        'jti': uuid.uuid4().hex,
    }
    pem = signing['private_key_pem']
    kid = (signing.get('kid') or '').strip()
    headers: dict[str, str] | None = {'kid': kid} if kid else None
    token = jwt.encode(claims, pem, algorithm='RS256', headers=headers)
    return token.decode('utf-8') if isinstance(token, bytes) else str(token)


# Identity ``d7fe351``+ ``_delegated_authority_fixed_payload``: exactly 15 keys on every **200** JSON (no extras).
_DELEGATED_AUTHORITY_RESPONSE_KEYS = frozenset(
    {
        'authorized',
        'active',
        'revoked',
        'paused',
        'agent_id',
        'company_id',
        'global_agent_id',
        'global_company_id',
        'grant_version',
        'company_binding_version',
        'access_mode',
        'read_level',
        'allow_destructive',
        'services_allowed',
        'revoked_at',
    }
)


def _delegated_authority_success_body_ok(
    data: dict[str, Any],
    *,
    agent_id: str,
    company_id: int,
    global_company_id: str,
    grant_version: int,
    company_binding_version: int,
    agent_claims: dict[str, Any] | None,
) -> bool:
    """Require Identity **200** JSON to match ``_delegated_authority_fixed_payload`` (merged ``develop``).

    For **delegated** JWTs (full global triple), the signed claims must include a valid
    ``global_agent_id`` matching the Identity row, ``mcp_destructive`` as a real **bool**
    matching ``allow_destructive`` (no string/coercion fallback), and JWT ``scope`` must
    match ``services_allowed`` as an exact **set** (order-independent).
    """
    if set(data.keys()) != _DELEGATED_AUTHORITY_RESPONSE_KEYS:
        return False
    if data.get('authorized') is not True:
        return False
    if data.get('active') is not True:
        return False
    if data.get('revoked') is not False:
        return False
    if data.get('paused') is not False:
        return False
    row_allow_destr = data.get('allow_destructive')
    if not isinstance(row_allow_destr, bool):
        return False
    delegated_claims = isinstance(agent_claims, dict) and is_global_delegated_claims(agent_claims)
    jwt_destr = agent_claims.get('mcp_destructive') if isinstance(agent_claims, dict) else None
    if delegated_claims:
        if 'mcp_destructive' not in (agent_claims or {}) or not isinstance(jwt_destr, bool):
            return False
        if row_allow_destr != jwt_destr:
            return False
    elif isinstance(jwt_destr, bool):
        if row_allow_destr != jwt_destr:
            return False
    elif row_allow_destr is not False:
        return False
    try:
        aid = uuid.UUID(str(data.get('agent_id') or '').strip())
        expect_aid = uuid.UUID(str(agent_id).strip())
    except (ValueError, TypeError, AttributeError):
        return False
    if aid != expect_aid:
        return False
    cid_raw = data.get('company_id')
    if not isinstance(cid_raw, int) or cid_raw <= 0:
        return False
    if int(cid_raw) != int(company_id):
        return False
    try:
        row_gc = uuid.UUID(str(data.get('global_company_id') or '').strip())
        body_gc = uuid.UUID(str(global_company_id).strip())
    except (ValueError, TypeError, AttributeError):
        return False
    if row_gc != body_gc:
        return False
    gv_raw = data.get('grant_version')
    cb_raw = data.get('company_binding_version')
    if not isinstance(gv_raw, int) or not isinstance(cb_raw, int):
        return False
    if int(gv_raw) != int(grant_version) or int(cb_raw) != int(company_binding_version):
        return False
    ga_raw = data.get('global_agent_id')
    if not isinstance(ga_raw, str) or not ga_raw.strip():
        return False
    try:
        resp_ga = uuid.UUID(ga_raw.strip())
    except (ValueError, TypeError, AttributeError):
        return False
    if not isinstance(data.get('access_mode'), str) or not str(data.get('access_mode') or '').strip():
        return False
    if not isinstance(data.get('read_level'), str) or not str(data.get('read_level') or '').strip():
        return False
    svcs = data.get('services_allowed')
    if not isinstance(svcs, list) or not all(isinstance(x, str) for x in svcs):
        return False
    if svcs != sorted(svcs):
        return False
    ra = data.get('revoked_at')
    if ra is not None and not isinstance(ra, int):
        return False
    if isinstance(agent_claims, dict) and agent_claims:
        raw_ga = agent_claims.get('global_agent_id')
        if delegated_claims:
            if raw_ga in (None, ''):
                return False
            try:
                claim_ga = uuid.UUID(str(raw_ga).strip())
            except (ValueError, TypeError, AttributeError):
                return False
            if claim_ga != resp_ga:
                return False
        elif raw_ga not in (None, ''):
            try:
                claim_ga = uuid.UUID(str(raw_ga).strip())
            except (ValueError, TypeError, AttributeError):
                return False
            if claim_ga != resp_ga:
                return False
        jwt_access = str(agent_claims.get('mcp_access') or '').strip().lower()
        jwt_read = str(agent_claims.get('mcp_read') or '').strip().lower()
        if jwt_access and str(data.get('access_mode') or '').strip().lower() != jwt_access:
            return False
        if jwt_read and str(data.get('read_level') or '').strip().lower() != jwt_read:
            return False
        try:
            from shellui_django.mcp.gateway import scope_service_ids
        except ImportError:
            scope_service_ids = None  # type: ignore[misc, assignment]
        if scope_service_ids is not None:
            claim_set = {str(x) for x in scope_service_ids(agent_claims) if str(x).strip()}
            row_set = {str(x) for x in svcs if isinstance(x, str) and str(x).strip()}
            if claim_set != row_set:
                return False
    return True


class DelegatedAuthorityFailureReason(str, Enum):
    ok = 'ok'
    identity_not_configured = 'identity_not_configured'
    signing_not_configured = 'signing_not_configured'
    transport_error = 'transport_error'
    http_not_200 = 'http_not_200'
    invalid_json = 'invalid_json'
    not_authorized = 'not_authorized'
    binding_or_shape_mismatch = 'binding_or_shape_mismatch'


@dataclass(frozen=True, slots=True)
class DelegatedAuthorityResult:
    ok: bool
    reason: DelegatedAuthorityFailureReason = DelegatedAuthorityFailureReason.ok
    http_status: int | None = None


def verify_live_delegated_agent_authority_detail(
    *,
    agent_id: str,
    company_id: int,
    global_company_id: str,
    grant_version: int,
    company_binding_version: int,
    agent_claims: dict[str, Any] | None = None,
) -> DelegatedAuthorityResult:
    """
    Live delegated binding check against Identity (not revocation-cache alone).

    **200** responses use a **fixed 15-key** JSON object (see identity ``_delegated_authority_fixed_payload``).
    The gateway accepts only when ``authorized`` and ``active`` are **true**, ``revoked`` and ``paused`` are
    **false**, binding IDs and versions match the request, ``services_allowed`` is a sorted list of strings,
    ``allow_destructive`` is a **boolean** that must match the JWT ``mcp_destructive`` claim when present,
    and there are **no** extra keys. For delegated JWTs, ``global_agent_id`` and boolean ``mcp_destructive``
    are **required** and must match the row. Mismatch can still be **HTTP 200** with ``authorized: false``;
    the gateway treats that as deny. Transport errors and non-200 → deny.
    When ``agent_claims`` is set, ``mcp_access`` / ``mcp_read``, JWT ``scope`` (full set vs row), and
    ``global_agent_id`` (delegated) must match the Identity row.
    """
    origin = _identity_origin()
    if not origin:
        logger.warning('MCP delegated authority check skipped: Identity is not configured')
        return DelegatedAuthorityResult(False, reason=DelegatedAuthorityFailureReason.identity_not_configured)
    audience = _identity_audience(origin)
    try:
        assertion = _build_delegated_agent_authority_assertion(audience_url=audience)
    except InternalAssertionError:
        logger.warning('MCP delegated authority check skipped: service assertion signing is not configured')
        return DelegatedAuthorityResult(False, reason=DelegatedAuthorityFailureReason.signing_not_configured)
    url = f'{origin.rstrip("/")}{DELEGATED_AGENT_AUTHORITY_PATH}'
    body: dict[str, Any] = {
        'agent_id': str(agent_id).strip(),
        'company_id': int(company_id),
        'global_company_id': str(global_company_id).strip(),
        'grant_version': int(grant_version),
        'company_binding_version': int(company_binding_version),
    }
    try:
        response = _http_post(
            url,
            json=body,
            headers={'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'},
            timeout=5,
        )
    except requests.RequestException as exc:
        logger.warning('MCP delegated authority check transport error: %s', type(exc).__name__)
        return DelegatedAuthorityResult(False, reason=DelegatedAuthorityFailureReason.transport_error)
    if response.status_code != 200:
        logger.info(
            'MCP delegated authority rejected: status=%s agent_id=%s company_id=%s',
            response.status_code,
            agent_id,
            company_id,
        )
        return DelegatedAuthorityResult(
            False,
            reason=DelegatedAuthorityFailureReason.http_not_200,
            http_status=int(response.status_code),
        )
    try:
        data = response.json()
    except ValueError:
        return DelegatedAuthorityResult(False, reason=DelegatedAuthorityFailureReason.invalid_json)
    if not isinstance(data, dict):
        return DelegatedAuthorityResult(False, reason=DelegatedAuthorityFailureReason.invalid_json)
    if data.get('authorized') is not True or data.get('active') is not True:
        return DelegatedAuthorityResult(False, reason=DelegatedAuthorityFailureReason.not_authorized, http_status=200)
    if not _delegated_authority_success_body_ok(
        data,
        agent_id=agent_id,
        company_id=company_id,
        global_company_id=global_company_id,
        grant_version=grant_version,
        company_binding_version=company_binding_version,
        agent_claims=agent_claims,
    ):
        logger.info(
            'MCP delegated authority response rejected: binding echo mismatch or invalid shape agent_id=%s company_id=%s',
            agent_id,
            company_id,
        )
        return DelegatedAuthorityResult(
            False, reason=DelegatedAuthorityFailureReason.binding_or_shape_mismatch, http_status=200
        )
    return DelegatedAuthorityResult(True)


def verify_live_delegated_agent_authority(
    *,
    agent_id: str,
    company_id: int,
    global_company_id: str,
    grant_version: int,
    company_binding_version: int,
    agent_claims: dict[str, Any] | None = None,
) -> bool:
    return verify_live_delegated_agent_authority_detail(
        agent_id=agent_id,
        company_id=company_id,
        global_company_id=global_company_id,
        grant_version=grant_version,
        company_binding_version=company_binding_version,
        agent_claims=agent_claims,
    ).ok


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
        logger.warning('MCP revocation poll failed: service assertion signing is not configured')
        _mark_revocation_untrusted()
        return False
    response: requests.Response | None = None
    for attempt in range(12):
        try:
            response = requests.get(url, headers=headers, timeout=5)
        except requests.RequestException as exc:
            logger.warning('MCP revocation poll failed: %s', type(exc).__name__)
            response = None
        if response is None or int(response.status_code) >= 500:
            if attempt < 11:
                time.sleep(1.0)
            continue
        break
    if response is None:
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
