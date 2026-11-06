"""Identity revocation polling and MCP call log forwarding."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from typing import Any

import jwt
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

from apps.connector.mcp_audit_codes import sanitize_error_code
from apps.connector.mcp_call_audit import OUTCOMES, legacy_result_token, safe_route_path_for_audit
from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_revocation import revocation_fingerprint_material
from apps.connector.mcp_setup_context import parse_global_company_id, parse_int_version_claim

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
    """Require Identity **200** JSON to match ``_delegated_authority_fixed_payload`` (merged ``develop``)."""
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
    if data.get('allow_destructive') is not False:
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
        if raw_ga not in (None, ''):
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
            claim_svcs = sorted(str(x) for x in scope_service_ids(agent_claims))
            if claim_svcs != list(svcs):
                return False
    return True


def verify_live_delegated_agent_authority(
    *,
    agent_id: str,
    company_id: int,
    global_company_id: str,
    grant_version: int,
    company_binding_version: int,
    agent_claims: dict[str, Any] | None = None,
) -> bool:
    """
    Live delegated binding check against Identity (not revocation-cache alone).

    **200** responses use a **fixed 15-key** JSON object (see identity ``_delegated_authority_fixed_payload``).
    The gateway accepts only when ``authorized`` and ``active`` are **true**, ``revoked`` / ``paused`` /
    ``allow_destructive`` are **false**, binding fields match the request, ``services_allowed`` is a
    sorted list of strings, and there are **no** extra keys. Mismatch can still be **HTTP 200** with
    ``authorized: false``; the gateway treats that as deny. Transport errors and non-200 → deny.
    When ``agent_claims`` is set, ``global_agent_id`` (if present), ``mcp_access`` / ``mcp_read``, and
    JWT ``scope`` services must match the Identity row (``access_mode``, ``read_level``, ``services_allowed``).
    """
    origin = _identity_origin()
    if not origin:
        logger.warning('MCP delegated authority check skipped: Identity is not configured')
        return False
    audience = _identity_audience(origin)
    try:
        assertion = _build_delegated_agent_authority_assertion(audience_url=audience)
    except InternalAssertionError:
        logger.warning('MCP delegated authority check skipped: service assertion signing is not configured')
        return False
    url = f'{origin.rstrip("/")}{DELEGATED_AGENT_AUTHORITY_PATH}'
    body: dict[str, Any] = {
        'agent_id': str(agent_id).strip(),
        'company_id': int(company_id),
        'global_company_id': str(global_company_id).strip(),
        'grant_version': int(grant_version),
        'company_binding_version': int(company_binding_version),
    }
    try:
        response = requests.post(
            url,
            json=body,
            headers={'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'},
            timeout=5,
        )
    except requests.RequestException as exc:
        logger.warning('MCP delegated authority check transport error: %s', type(exc).__name__)
        return False
    if response.status_code != 200:
        logger.info(
            'MCP delegated authority rejected: status=%s agent_id=%s company_id=%s',
            response.status_code,
            agent_id,
            company_id,
        )
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
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
        return False
    return True


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


_ACCESS_KINDS = frozenset({'read', 'write', 'destructive'})


def _identity_ingest_outcome(*, outcome: str, log_result: str | None) -> str:
    o = str(outcome or '').strip().lower()
    if o == 'pending':
        o = 'pending_approval'
    if o == 'session_used':
        return 'session_used'
    if o == 'allowed':
        return 'allowed'
    if o == 'failed':
        return 'failed'
    if o == 'denied':
        return 'denied'
    if o == 'pending_approval':
        return 'waiting_approval'
    lr = str(log_result or '').strip().lower() if log_result else ''
    if lr == 'pending':
        lr = 'pending_approval'
    eff = o if o in OUTCOMES else lr
    if eff not in OUTCOMES:
        eff = 'failed'
    token = legacy_result_token(outcome=eff)
    if token == 'success':
        return 'allowed'
    if token == 'error':
        return 'failed'
    if token == 'denied':
        return 'denied'
    if token == 'pending_approval':
        return 'waiting_approval'
    return 'failed'


def forward_call_log(entry: dict) -> None:
    origin = _identity_origin()
    if not origin:
        return
    url = f'{origin}/api/v1/mcp/internal/mcp-call-logs'
    try:
        assertion = build_mcp_call_log_assertion(audience_url=_identity_audience(origin), **_signing_kwargs())
    except InternalAssertionError:
        logger.warning('MCP call log failed: service assertion signing is not configured')
        return
    raw_aid = entry.get('agent_id')
    try:
        agent_uuid = uuid.UUID(str(raw_aid).strip())
    except (TypeError, ValueError, AttributeError):
        logger.warning('MCP call log skipped: invalid agent_id')
        return
    cid = strict_numeric_company_id(entry.get('company_id'))
    if cid is None:
        logger.warning('MCP call log skipped: invalid company_id')
        return
    gv_log = parse_int_version_claim(entry.get('grant_version'))
    if gv_log is None:
        logger.warning('MCP call log skipped: grant_version missing or invalid')
        return
    gcid_log = parse_global_company_id(entry.get('global_company_id'))
    cbv_log = parse_int_version_claim(entry.get('company_binding_version'))
    delegated = gcid_log is not None and cbv_log is not None
    if gcid_log is not None and cbv_log is None:
        logger.warning('MCP call log skipped: partial delegated global binding')
        return
    if gcid_log is None and cbv_log is not None:
        logger.warning('MCP call log skipped: partial delegated global binding')
        return
    outcome_raw = str(entry.get('outcome') or '').strip().lower()
    log_res = str(entry.get('log_result') or '').strip() if entry.get('log_result') is not None else None
    ingest_outcome = _identity_ingest_outcome(outcome=outcome_raw, log_result=log_res)
    access_raw = str(entry.get('access_kind') or entry.get('access_level') or '').strip().lower()
    access_kind = access_raw if access_raw in _ACCESS_KINDS else 'unknown'
    tool_name = str(entry.get('tool_export_id') or entry.get('tool') or '')[:255] or 'tool'
    safe_path = safe_route_path_for_audit(entry.get('path'))[:500]
    internal_for_legacy = ingest_outcome
    if internal_for_legacy == 'waiting_approval':
        internal_for_legacy = 'pending_approval'
    if internal_for_legacy not in OUTCOMES:
        internal_for_legacy = 'failed'
    legacy_res = str(entry.get('result') or '').strip().lower()[:32]
    if not legacy_res:
        legacy_res = legacy_result_token(outcome=internal_for_legacy)
    aid_raw = str(entry.get('approval_id') or entry.get('approval_request_id') or '').strip()
    approval_uuid: str | None = None
    if aid_raw:
        try:
            approval_uuid = str(uuid.UUID(aid_raw))
        except (ValueError, TypeError, AttributeError):
            approval_uuid = None
    duration = entry.get('duration_ms')
    dur_ms = int(duration) if isinstance(duration, (int, float)) and duration >= 0 else 0
    client_ip = str(entry.get('client_ip') or '').strip()[:45]
    ec_raw = entry.get('error_code')
    error_code_val = (sanitize_error_code(ec_raw) or '') if ec_raw is not None else ''
    body: dict[str, Any] = {
        'agent_id': str(agent_uuid),
        'company_id': int(cid),
        'grant_version': int(gv_log),
        'service': str(entry.get('service') or 'ai')[:32],
        'tool': tool_name,
        'method': str(entry.get('method') or '')[:10],
        'path': safe_path,
        'status': int(entry.get('status') or 0),
        'duration_ms': dur_ms,
        'client_ip': client_ip,
        'result': legacy_res,
        'outcome': ingest_outcome,
        'access_kind': access_kind,
        'error_code': error_code_val,
    }
    if delegated:
        body['global_company_id'] = str(gcid_log)
        body['company_binding_version'] = int(cbv_log)
    if approval_uuid:
        body['approval_id'] = approval_uuid
    try:
        requests.post(
            url,
            json=body,
            headers={'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'},
            timeout=5,
        )
    except requests.RequestException as exc:
        logger.warning('MCP call log forward failed: %s', type(exc).__name__)
