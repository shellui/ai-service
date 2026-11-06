"""Identity MCP approval store (internal APIs) and connection session grants."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone as dt_timezone
from dataclasses import dataclass
from typing import Any

import jwt
import requests
from django.conf import settings
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from shellui_django.mcp.internal import (
    InternalAssertionError,
    build_mcp_approval_assertion,
)

from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_identity import (
    _identity_audience,
    _identity_origin,
    _signing_kwargs,
    agent_is_revoked,
)
from apps.connector.mcp_revocation import delegation_authority_consistent_with_revocation
from apps.connector.mcp_setup_context import (
    ApprovalAssertionContext,
    approval_assertion_context_from_agent_claims,
    parse_global_company_id,
    parse_int_version_claim,
    parse_setup_expires_at_claim,
    session_allow_ttl_bounds,
)

logger = logging.getLogger(__name__)

APPROVAL_REQUESTS_PATH = '/api/v1/mcp/internal/mcp-approval-requests'
APPROVAL_STATE_PATH = '/api/v1/mcp/internal/mcp-approval-state'
APPROVAL_CONSUME_PATH = '/api/v1/mcp/internal/mcp-approval-consume'
APPROVAL_DECIDE_PATH = '/api/v1/mcp/internal/mcp-approval-decide'
SESSION_CHECK_PATH = '/api/v1/mcp/internal/mcp-approval-session-check'
SESSION_REVOKE_PATH = '/api/v1/mcp/internal/mcp-approval-session-revoke'

# Ordinary (non-setup) session-allow upper bound from Identity ``expires_at`` (seconds).
SESSION_GRANT_SECONDS = 60

PUBLIC_APPROVALS_PATH = '/api/v1/mcp/approvals'

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


def _assertion_context(payload: dict[str, Any] | None) -> ApprovalAssertionContext:
    if not isinstance(payload, dict):
        return approval_assertion_context_from_agent_claims(None)
    inner = payload.get('_agent_claims')
    if isinstance(inner, dict):
        return approval_assertion_context_from_agent_claims(inner)
    return approval_assertion_context_from_agent_claims(None)


def _parse_iso_expires_at(raw: object) -> timezone.datetime | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(raw), tz=dt_timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
        return dt if dt > timezone.now() else None
    text = str(raw).strip()
    if not text:
        return None
    dt = parse_datetime(text)
    return dt


def _build_approval_assertion_jwt(*, binding: dict[str, Any], ctx: ApprovalAssertionContext) -> str:
    """RS256 JWT via commons ``build_mcp_approval_assertion`` plus optional setup claims."""
    signing = _signing_kwargs()
    origin = _identity_origin()
    if not origin:
        raise InternalAssertionError('Identity is not configured.', status=503)
    issuer = (getattr(settings, 'AI_SERVICE_ISSUER', '') or '').strip().rstrip('/')
    if not issuer:
        raise InternalAssertionError('AI_SERVICE_ISSUER is not configured.', status=503)
    target = _identity_audience(origin)
    gv = ctx.grant_version
    gcid = ctx.global_company_id
    cbv = ctx.company_binding_version
    if ctx.is_personal_agent:
        token = build_mcp_approval_assertion(
            company_id=int(binding['company_id']),
            agent_id=str(binding['agent_id']),
            service=str(binding['service']),
            action=str(binding['action']),
            arguments_hash=str(binding['arguments_hash']),
            audience_url=target,
            lifetime_seconds=int(ctx.lifetime_seconds),
            private_key_pem=signing['private_key_pem'],
            kid=signing['kid'],
            issuer=issuer,
            grant_version=gv,
            global_company_id=None,
            company_binding_version=None,
        )
    else:
        if gv is None or gcid is None or cbv is None:
            raise InternalAssertionError('Delegated approval assertion requires grant snapshot.', status=503)
        token = build_mcp_approval_assertion(
            company_id=int(binding['company_id']),
            agent_id=str(binding['agent_id']),
            service=str(binding['service']),
            action=str(binding['action']),
            arguments_hash=str(binding['arguments_hash']),
            audience_url=target,
            lifetime_seconds=int(ctx.lifetime_seconds),
            private_key_pem=signing['private_key_pem'],
            kid=signing['kid'],
            issuer=issuer,
            grant_version=int(gv),
            global_company_id=str(gcid),
            company_binding_version=int(cbv),
        )
    if ctx.setup_flow and ctx.mcp_session_ttl_seconds is not None:
        try:
            claims = jwt.decode(token, options={'verify_signature': False})
        except jwt.PyJWTError as exc:
            raise InternalAssertionError('Could not merge setup approval claims.', status=503) from exc
        if not isinstance(claims, dict):
            raise InternalAssertionError('Could not merge setup approval claims.', status=503)
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
            logger.warning('MCP approval assertion re-encode failed: %s', type(exc).__name__)
            raise InternalAssertionError('Could not sign approval assertion.', status=503) from exc
        if isinstance(token, bytes):
            token = token.decode('utf-8')
    return token if isinstance(token, str) else str(token)


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
    if ctx.blocked_assertion:
        logger.warning('MCP approval create skipped: invalid setup claims for delegated token')
        return None
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
    if ctx.blocked_assertion:
        return None, None
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
    if ctx.blocked_assertion:
        return False
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
    return isinstance(data, dict) and data.get('consumed') is True


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
    if ctx.blocked_assertion:
        return DecideResult(ok=False, status_code=503)
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


def _str_claim(agent_claims: dict[str, Any], key: str) -> str:
    return str(agent_claims.get(key) or '').strip()


def _expected_versions_from_agent_claims(
    agent_claims: dict[str, Any],
) -> tuple[int | None, int | None]:
    return parse_int_version_claim(agent_claims.get('grant_version')), parse_int_version_claim(
        agent_claims.get('company_binding_version'),
    )


def _session_response_versions(data: dict[str, Any]) -> tuple[int | None, int | None]:
    return parse_int_version_claim(data.get('grant_version')), parse_int_version_claim(
        data.get('company_binding_version'),
    )


def _parse_setup_expires_at_from_response(raw: object, *, wall_max_exp: int) -> timezone.datetime | None:
    """Parse Identity ``setup_expires_at`` (ISO or Unix epoch seconds); rejects bool; never stringify ``None``."""
    return parse_setup_expires_at_claim(raw, wall_max_exp=wall_max_exp)


def _cap_session_expiry(
    exp_dt: timezone.datetime | None,
    *,
    ag: dict[str, Any],
    ctx: ApprovalAssertionContext,
    setup_resp_dt: timezone.datetime | None,
) -> timezone.datetime | None:
    """Combine Identity expires_at with JWT wall and setup caps (fail closed)."""
    wall_sec = _seconds_until_jwt_exp(ag)
    if wall_sec is not None and wall_sec <= 0:
        return None
    now = timezone.now()
    candidates: list[timezone.datetime] = []
    if exp_dt is not None:
        candidates.append(exp_dt)
    if wall_sec is not None:
        candidates.append(now + timedelta(seconds=int(wall_sec)))
    if ctx.setup_flow and ctx.mcp_session_ttl_seconds is not None:
        candidates.append(now + timedelta(seconds=int(ctx.mcp_session_ttl_seconds)))
    if ctx.setup_flow and ctx.setup_expires_at is not None:
        candidates.append(ctx.setup_expires_at)
    if setup_resp_dt is not None:
        candidates.append(setup_resp_dt)
    if not candidates:
        return None
    return min(candidates)


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
        return False
    ag = _agent_claims_from_payload(payload)
    expected_gv, expected_cbv = _expected_versions_from_agent_claims(ag)
    expected_gcid = parse_global_company_id(ag.get('global_company_id'))
    ctx = _assertion_context(payload)
    if ctx.blocked_assertion:
        return False
    personal = ctx.is_personal_agent
    if not personal:
        if expected_gv is None or expected_cbv is None or expected_gcid is None:
            return False
        if not delegation_authority_consistent_with_revocation(
            agent_id=agent_id,
            company_id=company_id,
            agent_claims=ag,
        ):
            return False
    else:
        if (expected_gv is None) != (expected_cbv is None):
            return False
    try:
        wall_max_exp = int(ag['exp'])
    except (KeyError, TypeError, ValueError):
        wall_max_exp = int(time.time())

    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return False
    url = f'{origin.rstrip("/")}{SESSION_CHECK_PATH}'
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        return False
    body: dict[str, Any] = {
        'connection_id': connection_id,
        'is_destructive': bool(is_destructive),
        'agent_id': agent_id,
        'company_id': company_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
    }
    if expected_gv is not None:
        body['grant_version'] = int(expected_gv)
    if expected_cbv is not None:
        body['company_binding_version'] = int(expected_cbv)
    if expected_gcid is not None:
        body['global_company_id'] = str(expected_gcid)
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
    if not isinstance(data, dict):
        return False
    if not data.get('session_allowed'):
        return False
    resp_gv, resp_cbv = _session_response_versions(data)
    resp_gcid = parse_global_company_id(data.get('global_company_id'))

    expires_at = data.get('expires_at')
    exp_dt = _parse_iso_expires_at(expires_at)
    if exp_dt is not None:
        if timezone.is_naive(exp_dt):
            exp_dt = timezone.make_aware(exp_dt, timezone.get_current_timezone())
        if exp_dt <= timezone.now():
            return False

    setup_resp_dt = _parse_setup_expires_at_from_response(data.get('setup_expires_at'), wall_max_exp=wall_max_exp)
    if ctx.setup_flow and setup_resp_dt is None:
        return False

    if agent_is_revoked(agent_id, company_id):
        return False
    wall = _seconds_until_jwt_exp(ag)
    if wall is not None and wall <= 0:
        return False

    if exp_dt is None:
        return False

    now = timezone.now()
    ordinary_window_end = now + timedelta(seconds=int(SESSION_GRANT_SECONDS))
    version_mismatch = resp_gv != expected_gv or resp_cbv != expected_cbv
    if not personal:
        if resp_gcid is not None and expected_gcid is not None and resp_gcid != expected_gcid:
            return False
        if version_mismatch:
            if ctx.setup_flow:
                return False
            if not (exp_dt <= ordinary_window_end):
                return False
    elif expected_gv is not None or expected_cbv is not None:
        if version_mismatch:
            return False

    cap_dt = _cap_session_expiry(exp_dt, ag=ag, ctx=ctx, setup_resp_dt=setup_resp_dt)
    if cap_dt is None or cap_dt <= timezone.now():
        return False

    ordinary_max = timezone.now() + timedelta(seconds=int(SESSION_GRANT_SECONDS))
    if not ctx.setup_flow and cap_dt > ordinary_max:
        return False

    if ctx.setup_flow:
        lo, hi = session_allow_ttl_bounds()
        setup_max = timezone.now() + timedelta(seconds=int(hi))
        if cap_dt > setup_max:
            return False

    return True


def revoke_session_grant(payload: dict[str, Any], *, connection_id: str) -> bool:
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return False
    url = f'{origin.rstrip("/")}{SESSION_REVOKE_PATH}'
    ctx = _assertion_context(payload)
    if ctx.blocked_assertion:
        return False
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
