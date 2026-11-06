"""Identity MCP approval store (internal APIs) and connection session grants."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import timedelta
from dataclasses import dataclass
from typing import Any, TypedDict

import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from shellui_django.mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    InternalAssertionError,
)

from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_identity import (
    _identity_audience,
    _identity_origin,
    _signing_kwargs,
    agent_is_revoked,
    revocation_list_fingerprint,
)
from apps.connector.mcp_setup_context import ApprovalAssertionContext, approval_assertion_context_from_agent_claims

logger = logging.getLogger(__name__)

APPROVAL_REQUESTS_PATH = '/api/v1/mcp/internal/mcp-approval-requests'
APPROVAL_STATE_PATH = '/api/v1/mcp/internal/mcp-approval-state'
APPROVAL_CONSUME_PATH = '/api/v1/mcp/internal/mcp-approval-consume'
APPROVAL_DECIDE_PATH = '/api/v1/mcp/internal/mcp-approval-decide'
SESSION_CHECK_PATH = '/api/v1/mcp/internal/mcp-approval-session-check'
SESSION_REVOKE_PATH = '/api/v1/mcp/internal/mcp-approval-session-revoke'

# Default session-allow length and cache cap when Identity omits ``expires_at`` on session-check.
SESSION_GRANT_SECONDS = 60

PUBLIC_APPROVALS_PATH = '/api/v1/mcp/approvals'

_GRANT_MAP_PREFIX = 'mcp_gateway:session_grant_map:'
_GRANT_INDEX_PREFIX = 'mcp_gateway:session_grant_index:'


class _GrantRecord(TypedDict):
    exp_ms: int
    revoke_fp: str
    jti: str
    grant_ver: str


def _agent_claims_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    inner = payload.get('_agent_claims')
    return inner if isinstance(inner, dict) else {}


def _jwt_absolute_exp_ms(agent_claims: dict[str, Any]) -> int | None:
    try:
        exp = int(agent_claims['exp'])
    except (KeyError, TypeError, ValueError):
        return None
    return max(0, exp) * 1000


def _seconds_until_jwt_exp(agent_claims: dict[str, Any]) -> int | None:
    try:
        exp = int(agent_claims['exp'])
    except (KeyError, TypeError, ValueError):
        return None
    return max(0, int(exp - time.time()))


def _grant_index_key(*, agent_id: str, company_id: int) -> str:
    return f'{_GRANT_INDEX_PREFIX}{agent_id}:{company_id}'


def _invalidate_session_grant_maps_for_agent(*, agent_id: str, company_id: int) -> None:
    """Drop cached session grants after Identity revoke or agent revocation."""
    idx_key = _grant_index_key(agent_id=agent_id, company_id=company_id)
    raw = cache.get(idx_key)
    if isinstance(raw, dict):
        for map_key in raw:
            if isinstance(map_key, str):
                cache.delete(map_key)
    cache.delete(idx_key)


def _register_grant_map_key(*, agent_id: str, company_id: int, map_key: str, until_ms: int) -> None:
    idx_key = _grant_index_key(agent_id=agent_id, company_id=company_id)
    entry = cache.get(idx_key)
    m: dict[str, int] = dict(entry) if isinstance(entry, dict) else {}
    m[map_key] = max(int(m.get(map_key, 0)), int(until_ms))
    now = _now_ms()
    pruned = {k: v for k, v in m.items() if v > now}
    longest = max(pruned.values()) if pruned else until_ms
    ttl = max(1, int((longest - now) / 1000) + 2)
    cache.set(idx_key, pruned, timeout=min(ttl, int(getattr(settings, 'MCP_SESSION_GRANT_INDEX_MAX_SECONDS', 3600))))


def _now_ms() -> int:
    return int(time.time() * 1000)


def _assertion_context(payload: dict[str, Any] | None) -> ApprovalAssertionContext:
    if not isinstance(payload, dict):
        return approval_assertion_context_from_agent_claims(None)
    inner = payload.get('_agent_claims')
    if isinstance(inner, dict):
        return approval_assertion_context_from_agent_claims(inner)
    return approval_assertion_context_from_agent_claims(None)


def _grant_map_key(*, connection_id: str, agent_id: str, company_id: int) -> str:
    return f'{_GRANT_MAP_PREFIX}{connection_id}:{agent_id}:{company_id}'


def _grant_entry_key(*, service: str, action: str, arguments_hash: str) -> str:
    return f'{service}\x00{action}\x00{arguments_hash}'


def _parse_iso_expires_at(raw: object) -> timezone.datetime | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    dt = parse_datetime(text)
    return dt


def _build_approval_assertion_jwt(*, binding: dict[str, Any], ctx: ApprovalAssertionContext) -> str:
    """RS256 JWT for Identity internal MCP approval APIs (same claims as shellui-django helper plus setup)."""
    signing = _signing_kwargs()
    origin = _identity_origin()
    if not origin:
        raise InternalAssertionError('Identity is not configured.', status=503)
    issuer = (getattr(settings, 'AI_SERVICE_ISSUER', '') or '').strip().rstrip('/')
    if not issuer:
        raise InternalAssertionError('AI_SERVICE_ISSUER is not configured.', status=503)
    target = _identity_audience(origin)
    now = int(time.time())
    claims: dict[str, Any] = {
        'iss': issuer,
        'aud': APPROVAL_AUDIENCE,
        'sub': f'agent:{binding["agent_id"]}',
        'scope': APPROVAL_SCOPE,
        'company_id': int(binding['company_id']),
        'agent_id': str(binding['agent_id']),
        'service': str(binding['service']),
        'action': str(binding['action']),
        'arguments_hash': str(binding['arguments_hash']),
        'target': target,
        'iat': now,
        'exp': now + int(ctx.lifetime_seconds),
        'jti': uuid.uuid4().hex,
    }
    if ctx.setup_flow and ctx.mcp_session_ttl_seconds is not None:
        claims['setup_flow'] = True
        claims['mcp_session_ttl_seconds'] = int(ctx.mcp_session_ttl_seconds)
        if ctx.setup_expires_at is not None:
            claims['setup_expires_at'] = ctx.setup_expires_at.isoformat()
    try:
        token = jwt.encode(
            claims,
            signing['private_key_pem'],
            algorithm='RS256',
            headers={'kid': signing['kid']} if signing.get('kid') else None,
        )
    except Exception as exc:
        logger.warning('MCP approval assertion encode failed: %s', type(exc).__name__)
        raise InternalAssertionError('Could not sign approval assertion.', status=503) from exc
    return token.decode('utf-8') if isinstance(token, bytes) else token


def _approval_headers(binding: dict[str, Any], *, ctx: ApprovalAssertionContext) -> dict[str, str]:
    assertion = _build_approval_assertion_jwt(binding=binding, ctx=ctx)
    return {'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'}


@dataclass(frozen=True, slots=True)
class DecideResult:
    ok: bool
    status_code: int
    audit_status: str | None = None
    approval_status: str | None = None


def approval_binding_from_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    agent_id = str(payload.get('agent_id') or '').strip()
    company_id = payload.get('company_id')
    service = str(payload.get('service') or '').strip()
    action = str(payload.get('action') or '').strip()
    arguments_hash = str(payload.get('arguments_hash') or '').strip()
    if not agent_id or company_id is None or not service or not action or not arguments_hash:
        return None
    cid = strict_numeric_company_id(company_id)
    if cid is None:
        return None
    return {
        'agent_id': agent_id,
        'company_id': cid,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
    }


def create_approval_request(payload: dict[str, Any], *, is_destructive: bool = False) -> dict[str, Any] | None:
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return None
    url = f'{origin.rstrip("/")}{APPROVAL_REQUESTS_PATH}'
    body: dict[str, Any] = {
        'arguments': payload.get('arguments') or {},
        'is_destructive': bool(is_destructive),
    }
    summary = str(payload.get('short_action_summary') or '').strip()
    if summary:
        body['short_action_summary'] = summary[:500]
    method = str(payload.get('method') or '').strip()
    path = str(payload.get('path') or '').strip()
    if method and path:
        body['method'] = method
        body['path'] = path
    elif path:
        body['path'] = path
    ctx = _assertion_context(payload)
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        logger.warning('MCP approval create skipped: signing not configured')
        return None
    logger.info(
        'MCP approval create company_id=%s agent_id=%s service=%s action=%s destructive=%s setup_flow=%s',
        binding['company_id'],
        binding['agent_id'],
        binding['service'],
        binding['action'],
        bool(is_destructive),
        ctx.setup_flow,
    )
    try:
        response = requests.post(url, json=body, headers=headers, timeout=5)
    except requests.RequestException as exc:
        logger.warning('MCP approval create failed: %s', type(exc).__name__)
        return None
    if response.status_code >= 400:
        logger.warning('MCP approval create rejected: %s', response.status_code)
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict) or not data.get('id'):
        return None
    return {'id': str(data['id']), 'status': str(data.get('status') or 'pending')}


def fetch_approval_state(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (public status, approval_id when approved)."""
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return None, None
    url = f'{origin.rstrip("/")}{APPROVAL_STATE_PATH}'
    ctx = _assertion_context(payload)
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        return None, None
    try:
        response = requests.post(url, json={}, headers=headers, timeout=5)
    except requests.RequestException:
        return None, None
    if response.status_code == 404:
        return None, None
    if response.status_code >= 400:
        return None, None
    try:
        data = response.json()
    except ValueError:
        return None, None
    if not isinstance(data, dict):
        return None, None
    status = str(data.get('status') or '')
    approval_id = str(data.get('id') or '') if status == 'approved' else None
    return status or None, approval_id


def consume_approval(approval_id: str, payload: dict[str, Any]) -> bool:
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None or not approval_id:
        return False
    url = f'{origin.rstrip("/")}{APPROVAL_CONSUME_PATH}'
    ctx = _assertion_context(payload)
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        return False
    try:
        response = requests.post(
            url,
            json={'approval_id': approval_id},
            headers=headers,
            timeout=5,
        )
    except requests.RequestException:
        return False
    if response.status_code >= 400:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    return isinstance(data, dict) and bool(data.get('consumed'))


def decide_approval(
    *,
    approval_id: str,
    payload: dict[str, Any],
    decision: str,
    connection_id: str,
    actor_email: str | None = None,
) -> DecideResult:
    """Identity #134: decision is allow, deny, or allow_session."""
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None or not approval_id:
        return DecideResult(ok=False, status_code=503)
    url = f'{origin.rstrip("/")}{APPROVAL_DECIDE_PATH}'
    ctx = _assertion_context(payload)
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        return DecideResult(ok=False, status_code=503)
    body: dict[str, Any] = {
        'approval_id': approval_id,
        'decision': decision,
        'connection_id': connection_id,
    }
    if actor_email:
        body['actor_email'] = actor_email
    try:
        response = requests.post(url, json=body, headers=headers, timeout=5)
    except requests.RequestException:
        return DecideResult(ok=False, status_code=503)
    audit_status = None
    approval_status = None
    if response.status_code < 400:
        try:
            data = response.json()
            if isinstance(data, dict):
                audit_status = str(data.get('audit_status') or '') or None
                approval_status = str(data.get('status') or '') or None
        except ValueError:
            pass
    return DecideResult(
        ok=response.status_code < 400,
        status_code=response.status_code,
        audit_status=audit_status,
        approval_status=approval_status,
    )


def _revoke_fingerprint() -> str:
    return revocation_list_fingerprint() or ''


def _jti_from_agent_claims(agent_claims: dict[str, Any]) -> str:
    return str(agent_claims.get('jti') or '').strip()


def _prune_grant_map_records(
    m: dict[str, Any],
    *,
    now_ms: int,
    fp: str,
    jti: str,
    grant_ver: str,
) -> dict[str, _GrantRecord]:
    out: dict[str, _GrantRecord] = {}
    for k, v in m.items():
        if not isinstance(v, dict):
            continue
        try:
            exp_ms = int(v['exp_ms'])
        except (KeyError, TypeError, ValueError):
            continue
        if exp_ms <= now_ms:
            continue
        if str(v.get('revoke_fp') or '') != fp:
            continue
        if jti and str(v.get('jti') or '') != jti:
            continue
        if str(v.get('grant_ver', '')) != grant_ver:
            continue
        out[str(k)] = {
            'exp_ms': exp_ms,
            'revoke_fp': fp,
            'jti': str(v.get('jti') or ''),
            'grant_ver': grant_ver,
        }
    return out


def _session_check_grant_version(data: dict[str, Any]) -> str:
    """Identity #135: grant/permission version on session-check (field name TBD)."""
    for key in ('grant_validity_version', 'permission_version', 'session_grant_version', 'grant_version'):
        if key in data and data[key] is not None:
            return str(data[key])
    return ''


def _grant_version_from_agent_claims(agent_claims: dict[str, Any]) -> str:
    """When identity puts grant validity on the regional token, use it to invalidate stale cache."""
    for key in ('session_grant_version', 'grant_validity_version', 'permission_version'):
        if key in agent_claims and agent_claims[key] is not None:
            return str(agent_claims[key])
    return ''


def _setup_expires_at_cap_ms(ctx: ApprovalAssertionContext) -> int | None:
    if not ctx.setup_flow or ctx.setup_expires_at is None:
        return None
    return int(ctx.setup_expires_at.timestamp() * 1000)


def invalidate_local_session_grants_for_agent(*, agent_id: str, company_id: int) -> None:
    """Invalidate cached session-allow entries (e.g. after Identity session revoke)."""
    _invalidate_session_grant_maps_for_agent(agent_id=agent_id, company_id=company_id)


def _store_session_grant(
    *,
    payload: dict[str, Any],
    connection_id: str,
    agent_id: str,
    company_id: int,
    service: str,
    action: str,
    arguments_hash: str,
    expires_at_iso: str | None,
    grant_ver: str,
    setup_cap_ms: int | None,
) -> None:
    map_key = _grant_map_key(connection_id=connection_id, agent_id=agent_id, company_id=company_id)
    entry_k = _grant_entry_key(service=service, action=action, arguments_hash=arguments_hash)
    ag = _agent_claims_from_payload(payload)
    jti = _jti_from_agent_claims(ag)
    jwt_exp_ms = _jwt_absolute_exp_ms(ag)
    fp = _revoke_fingerprint()
    exp_dt = _parse_iso_expires_at(expires_at_iso)
    if exp_dt is not None:
        if timezone.is_naive(exp_dt):
            exp_dt = timezone.make_aware(exp_dt, timezone.get_current_timezone())
        grant_exp_ms = int(exp_dt.timestamp() * 1000)
    else:
        grant_exp_ms = _now_ms() + SESSION_GRANT_SECONDS * 1000
    if jwt_exp_ms is not None:
        grant_exp_ms = min(grant_exp_ms, jwt_exp_ms)
    if setup_cap_ms is not None:
        grant_exp_ms = min(grant_exp_ms, int(setup_cap_ms))
    now_ms = _now_ms()
    if grant_exp_ms <= now_ms:
        return
    record: _GrantRecord = {
        'exp_ms': grant_exp_ms,
        'revoke_fp': fp,
        'jti': jti,
        'grant_ver': grant_ver,
    }
    raw = cache.get(map_key)
    m = (
        _prune_grant_map_records(raw, now_ms=now_ms, fp=fp, jti=jti, grant_ver=grant_ver)
        if isinstance(raw, dict)
        else {}
    )
    m[entry_k] = record
    longest_ms = max(r['exp_ms'] for r in m.values()) if m else grant_exp_ms
    longest_remaining = max(1, int((longest_ms - now_ms) / 1000) + 1)
    idx_cap = int(getattr(settings, 'MCP_SESSION_GRANT_INDEX_MAX_SECONDS', 3600))
    cache.set(map_key, m, timeout=min(longest_remaining, idx_cap))
    _register_grant_map_key(
        agent_id=agent_id,
        company_id=company_id,
        map_key=map_key,
        until_ms=longest_ms,
    )


def check_session_grant(
    payload: dict[str, Any],
    *,
    connection_id: str,
    is_destructive: bool,
) -> bool:
    if is_destructive:
        return False
    agent_id = str(payload.get('agent_id') or '')
    cid = strict_numeric_company_id(payload.get('company_id'))
    if cid is None:
        return False
    company_id = cid
    service = str(payload.get('service') or '')
    action = str(payload.get('action') or '')
    arguments_hash = str(payload.get('arguments_hash') or '')
    if not connection_id or not agent_id or not service or not action or not arguments_hash:
        return False
    if agent_is_revoked(agent_id, company_id):
        invalidate_local_session_grants_for_agent(agent_id=agent_id, company_id=company_id)
        return False
    ag = _agent_claims_from_payload(payload)
    jti = _jti_from_agent_claims(ag)
    fp = _revoke_fingerprint()
    expected_grant_ver = _grant_version_from_agent_claims(ag)
    map_key = _grant_map_key(connection_id=connection_id, agent_id=agent_id, company_id=company_id)
    entry_k = _grant_entry_key(service=service, action=action, arguments_hash=arguments_hash)
    now_ms = _now_ms()
    raw = cache.get(map_key)
    if isinstance(raw, dict):
        rec = raw.get(entry_k)
        if isinstance(rec, dict):
            try:
                exp_ms = int(rec['exp_ms'])
            except (KeyError, TypeError, ValueError):
                exp_ms = 0
            rec_fp = str(rec.get('revoke_fp') or '')
            rec_jti = str(rec.get('jti') or '')
            rec_gv = str(rec.get('grant_ver') or '')
            if (
                exp_ms > now_ms
                and rec_fp == fp
                and (not jti or rec_jti == jti)
                and rec_gv == expected_grant_ver
                and not agent_is_revoked(agent_id, company_id)
            ):
                return True
        pruned = _prune_grant_map_records(
            raw,
            now_ms=now_ms,
            fp=fp,
            jti=jti,
            grant_ver=expected_grant_ver,
        )
        mismatch_had_entry = isinstance(rec, dict) and (
            str(rec.get('revoke_fp') or '') != fp or str(rec.get('grant_ver') or '') != expected_grant_ver
        )
        if pruned:
            longest_ms = max(r['exp_ms'] for r in pruned.values())
            longest_remaining = max(1, int((longest_ms - now_ms) / 1000) + 1)
            idx_cap = int(getattr(settings, 'MCP_SESSION_GRANT_INDEX_MAX_SECONDS', 3600))
            cache.set(map_key, pruned, timeout=min(longest_remaining, idx_cap))
        else:
            cache.delete(map_key)
        if mismatch_had_entry:
            raw = None

    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return False
    url = f'{origin.rstrip("/")}{SESSION_CHECK_PATH}'
    ctx = _assertion_context(payload)
    setup_cap_ms = _setup_expires_at_cap_ms(ctx)
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        return False
    body = {'connection_id': connection_id, 'is_destructive': bool(is_destructive)}
    try:
        response = requests.post(url, json=body, headers=headers, timeout=5)
    except requests.RequestException:
        return False
    if response.status_code >= 400:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    if isinstance(data, dict) and data.get('session_allowed'):
        sess_grant_ver = _session_check_grant_version(data)
        expires_at = data.get('expires_at')
        exp_dt = _parse_iso_expires_at(expires_at)
        if exp_dt is not None:
            if timezone.is_naive(exp_dt):
                exp_dt = timezone.make_aware(exp_dt, timezone.get_current_timezone())
            if exp_dt <= timezone.now():
                return False
        if agent_is_revoked(agent_id, company_id):
            invalidate_local_session_grants_for_agent(agent_id=agent_id, company_id=company_id)
            return False
        wall = _seconds_until_jwt_exp(ag)
        if wall is not None and wall <= 0:
            return False
        require_abs = bool(getattr(settings, 'MCP_SESSION_GRANT_REQUIRES_ABSOLUTE_EXPIRES_AT', False))
        if require_abs and ctx.setup_flow and exp_dt is None and setup_cap_ms is None:
            return False
        capped_iso: str | None = None
        if exp_dt is not None and wall is not None:
            cap_dt = timezone.now() + timedelta(seconds=wall)
            if exp_dt > cap_dt:
                capped_iso = cap_dt.isoformat()
            else:
                capped_iso = str(expires_at).strip() if expires_at else None
        elif exp_dt is not None:
            capped_iso = str(expires_at).strip() if expires_at else None
        elif wall is not None:
            capped_iso = (timezone.now() + timedelta(seconds=wall)).isoformat()
        _store_session_grant(
            payload=payload,
            connection_id=connection_id,
            agent_id=agent_id,
            company_id=company_id,
            service=service,
            action=action,
            arguments_hash=arguments_hash,
            expires_at_iso=capped_iso,
            grant_ver=sess_grant_ver,
            setup_cap_ms=setup_cap_ms,
        )
        return True
    return False


def revoke_session_grant(payload: dict[str, Any], *, connection_id: str) -> bool:
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return False
    url = f'{origin.rstrip("/")}{SESSION_REVOKE_PATH}'
    ctx = _assertion_context(payload)
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        return False
    try:
        response = requests.post(
            url,
            json={'connection_id': connection_id},
            headers=headers,
            timeout=5,
        )
    except requests.RequestException:
        return False
    if response.status_code >= 400:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    agent_id = str(payload.get('agent_id') or '')
    cid = strict_numeric_company_id(payload.get('company_id'))
    company_id = int(cid) if cid is not None else 0
    if agent_id and company_id:
        invalidate_local_session_grants_for_agent(agent_id=agent_id, company_id=company_id)
    return isinstance(data, dict) and bool(data.get('revoked'))


def session_grant_covers_write(
    payload: dict[str, Any],
    *,
    connection_id: str,
    is_destructive: bool,
) -> bool:
    return check_session_grant(payload, connection_id=connection_id, is_destructive=is_destructive)


def approval_settings_url(approval_id: str | None = None) -> str:
    template = getattr(settings, 'MCP_APPROVAL_SETTINGS_URL', '') or ''
    if template:
        if approval_id and '{approval_id}' in template:
            return template.format(approval_id=approval_id)
        if not approval_id:
            return template
    origin = (settings.IDENTITY_ISSUER or _identity_origin() or '').rstrip('/')
    base = f'{origin}{PUBLIC_APPROVALS_PATH}'
    if approval_id:
        return f'{base}/{approval_id}'
    return base


def approval_handler(payload: dict[str, Any]) -> dict[str, Any] | None:
    return create_approval_request(payload)


def approval_state(payload: dict[str, Any]) -> str | None:
    status, approval_id = fetch_approval_state(payload)
    if status == 'approved' and approval_id:
        payload['approval_id'] = approval_id
        return 'approved'
    if status == 'pending':
        return 'pending'
    if status == 'denied':
        return 'denied'
    if status == 'expired':
        return 'expired'
    return None


def approval_consume(approval_id: str, payload: dict[str, Any] | None = None) -> bool:
    return consume_approval(approval_id, payload or {})
