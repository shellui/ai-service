"""Identity MCP approval store (internal APIs) and connection session grants."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests
from django.conf import settings
from django.core.cache import cache
from shellui_django.mcp.internal import (
    InternalAssertionError,
    build_mcp_approval_assertion,
)

from apps.connector.mcp_identity import _identity_audience, _identity_origin, _signing_kwargs

logger = logging.getLogger(__name__)

APPROVAL_REQUESTS_PATH = '/api/v1/mcp/internal/mcp-approval-requests'
APPROVAL_STATE_PATH = '/api/v1/mcp/internal/mcp-approval-state'
APPROVAL_CONSUME_PATH = '/api/v1/mcp/internal/mcp-approval-consume'
APPROVAL_DECIDE_PATH = '/api/v1/mcp/internal/mcp-approval-decide'
SESSION_CHECK_PATH = '/api/v1/mcp/internal/mcp-approval-session-check'
SESSION_REVOKE_PATH = '/api/v1/mcp/internal/mcp-approval-session-revoke'

SESSION_GRANT_CACHE_PREFIX = 'mcp_gateway:session_grant:'
SESSION_GRANT_SECONDS = 60

PUBLIC_APPROVALS_PATH = '/api/v1/mcp/approvals'


@dataclass(frozen=True, slots=True)
class DecideResult:
    ok: bool
    status_code: int
    audit_status: str | None = None
    approval_status: str | None = None


def _approval_headers(binding: dict[str, Any]) -> dict[str, str]:
    origin = _identity_origin()
    if not origin:
        raise InternalAssertionError('Identity is not configured.', status=503)
    assertion = build_mcp_approval_assertion(
        audience_url=_identity_audience(origin),
        company_id=int(binding['company_id']),
        agent_id=str(binding['agent_id']),
        service=str(binding['service']),
        action=str(binding['action']),
        arguments_hash=str(binding['arguments_hash']),
        **_signing_kwargs(),
    )
    return {'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'}


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
    try:
        headers = _approval_headers(binding)
    except InternalAssertionError:
        logger.warning('MCP approval create skipped: signing not configured')
        return None
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
    try:
        headers = _approval_headers(binding)
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
    try:
        headers = _approval_headers(binding)
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
    try:
        headers = _approval_headers(binding)
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


def _session_grant_cache_key(*, connection_id: str, agent_id: str) -> str:
    return f'{SESSION_GRANT_CACHE_PREFIX}{connection_id}:{agent_id}'


def _cache_session_grant(*, connection_id: str, agent_id: str) -> None:
    if not connection_id or not agent_id:
        return
    cache.set(
        _session_grant_cache_key(connection_id=connection_id, agent_id=agent_id),
        True,
        timeout=SESSION_GRANT_SECONDS,
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
    if (
        connection_id
        and agent_id
        and cache.get(_session_grant_cache_key(connection_id=connection_id, agent_id=agent_id)) is True
    ):
        return True
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return False
    url = f'{origin.rstrip("/")}{SESSION_CHECK_PATH}'
    try:
        headers = _approval_headers(binding)
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
        _cache_session_grant(connection_id=connection_id, agent_id=agent_id)
        return True
    return False


def revoke_session_grant(payload: dict[str, Any], *, connection_id: str) -> bool:
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None:
        return False
    url = f'{origin.rstrip("/")}{SESSION_REVOKE_PATH}'
    try:
        headers = _approval_headers(binding)
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
    cache.delete(_session_grant_cache_key(connection_id=connection_id, agent_id=agent_id))
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
