"""Identity MCP approval store (internal APIs) and connection session grants."""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

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

from apps.connector.mcp_identity import _identity_audience, _identity_origin, _signing_kwargs
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
    try:
        cid = int(company_id)
    except (TypeError, ValueError):
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


def _prune_grant_map(m: dict[str, Any]) -> dict[str, int]:
    now = _now_ms()
    out: dict[str, int] = {}
    for k, v in m.items():
        if isinstance(v, int) and v > now:
            out[str(k)] = v
    return out


def _store_session_grant(
    *,
    connection_id: str,
    agent_id: str,
    company_id: int,
    service: str,
    action: str,
    arguments_hash: str,
    expires_at_iso: str | None,
) -> None:
    map_key = _grant_map_key(connection_id=connection_id, agent_id=agent_id, company_id=company_id)
    entry_k = _grant_entry_key(service=service, action=action, arguments_hash=arguments_hash)
    exp_dt = _parse_iso_expires_at(expires_at_iso)
    if exp_dt is not None:
        if timezone.is_naive(exp_dt):
            exp_dt = timezone.make_aware(exp_dt, timezone.get_current_timezone())
        exp_ms = int(exp_dt.timestamp() * 1000)
        remaining = (exp_dt - timezone.now()).total_seconds()
        ttl = max(1, int(remaining) + 1) if remaining > 0 else 0
    else:
        exp_ms = _now_ms() + SESSION_GRANT_SECONDS * 1000
        ttl = SESSION_GRANT_SECONDS
    if ttl <= 0:
        return
    raw = cache.get(map_key)
    m = _prune_grant_map(raw) if isinstance(raw, dict) else {}
    m[entry_k] = exp_ms
    longest_ms = max(m.values()) if m else exp_ms
    longest_remaining = max(1, int((longest_ms - _now_ms()) / 1000) + 1)
    cache.set(map_key, m, timeout=longest_remaining)


def check_session_grant(
    payload: dict[str, Any],
    *,
    connection_id: str,
    is_destructive: bool,
) -> bool:
    if is_destructive:
        return False
    agent_id = str(payload.get('agent_id') or '')
    try:
        company_id = int(payload.get('company_id'))
    except (TypeError, ValueError):
        return False
    service = str(payload.get('service') or '')
    action = str(payload.get('action') or '')
    arguments_hash = str(payload.get('arguments_hash') or '')
    if not connection_id or not agent_id or not service or not action or not arguments_hash:
        return False
    map_key = _grant_map_key(connection_id=connection_id, agent_id=agent_id, company_id=company_id)
    entry_k = _grant_entry_key(service=service, action=action, arguments_hash=arguments_hash)
    raw = cache.get(map_key)
    if isinstance(raw, dict):
        exp_ms = raw.get(entry_k)
        if isinstance(exp_ms, int) and _now_ms() < exp_ms:
            return True
        # Stale entry — drop and fall through to Identity.
        pruned = _prune_grant_map(raw)
        if pruned:
            longest_ms = max(pruned.values())
            longest_remaining = max(1, int((longest_ms - _now_ms()) / 1000) + 1)
            cache.set(map_key, pruned, timeout=longest_remaining)
        else:
            cache.delete(map_key)

    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return False
    url = f'{origin.rstrip("/")}{SESSION_CHECK_PATH}'
    ctx = _assertion_context(payload)
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
        expires_at = data.get('expires_at')
        exp_dt = _parse_iso_expires_at(expires_at)
        if exp_dt is not None:
            if timezone.is_naive(exp_dt):
                exp_dt = timezone.make_aware(exp_dt, timezone.get_current_timezone())
            if exp_dt <= timezone.now():
                return False
        _store_session_grant(
            connection_id=connection_id,
            agent_id=agent_id,
            company_id=company_id,
            service=service,
            action=action,
            arguments_hash=arguments_hash,
            expires_at_iso=str(expires_at).strip() if expires_at else None,
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
    try:
        company_id = int(payload.get('company_id'))
    except (TypeError, ValueError):
        company_id = 0
    if agent_id and company_id:
        cache.delete(_grant_map_key(connection_id=connection_id, agent_id=agent_id, company_id=company_id))
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
