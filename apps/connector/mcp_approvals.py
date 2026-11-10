"""Identity MCP approval store (internal APIs) and connection session grants."""

from __future__ import annotations

import contextvars
import hashlib
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
# Browser page on identity-service. Current develop serves it at this path and
# requires the signed ``fallback_path`` query. A future ``approval_url`` wins.
APPROVAL_PAGE_PATH = '/oauth/mcp/approval/{approval_id}'
_APPROVAL_CACHE_PREFIX = 'mcp_gateway:approval:'
_APPROVAL_CACHE_SECONDS = 900

CREATE_ERROR_UNREACHABLE = 'identity_unreachable'
CREATE_ERROR_SIGNING = 'signing_not_configured'
CREATE_ERROR_BLOCKED = 'blocked_assertion'
CREATE_ERROR_NOT_CONFIGURED = 'identity_not_configured'
CREATE_ERROR_REJECTED = 'identity_rejected'
CREATE_ERROR_INVALID = 'invalid_response'

_approval_create_error: contextvars.ContextVar[str] = contextvars.ContextVar(
    'mcp_approval_create_error',
    default='',
)


def identity_connection_id(raw: str) -> str:
    """
    Sanitize ``Mcp-Session-Id`` for Identity JSON bodies only (local session cache keeps the raw
    header). Printable ASCII, max 128 chars, no ``|``; else SHA-256 hex of UTF-8 bytes.
    """
    s = str(raw or '').strip()
    if not s:
        return ''
    if len(s) > 128 or '|' in s or any(ord(c) < 32 or ord(c) > 126 for c in s):
        return hashlib.sha256(s.encode('utf-8')).hexdigest()
    return s


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
    if not ctx.is_global_delegated:
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


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    consumed: bool
    status_code: int | None = None
    already_consumed: bool = False


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


def take_approval_create_error() -> str:
    """Return and clear the reason from the latest ``create_approval_request`` on this context."""
    code = _approval_create_error.get()
    _approval_create_error.set('')
    return code


def _set_create_error(code: str) -> None:
    _approval_create_error.set(code)


def _public_identity_origin() -> str:
    """Public origin for links a person opens. Prefer the issuer over an internal service URL."""
    return (getattr(settings, 'IDENTITY_ISSUER', None) or _identity_origin() or '').rstrip('/')


def _is_absolute_http_url(value: str) -> bool:
    text = str(value or '').strip()
    if not text or len(text) > 2048 or any(ch.isspace() for ch in text):
        return False
    lowered = text.lower()
    return lowered.startswith('https://') or lowered.startswith('http://')


def _safe_fallback_path(value: str) -> str:
    text = str(value or '').strip()
    if not text or len(text) > 2048 or any(ch.isspace() for ch in text):
        return ''
    if not text.startswith('/') or text.startswith('//') or '\\' in text:
        return ''
    return text


def resolve_approval_url(
    approval_id: str,
    *,
    approval_url: str = '',
    fallback_path: str = '',
) -> str:
    """Absolute page for one approval.

    Identity develop (``db5db3f``) returns ``fallback_path`` and no ``approval_url``.
    Prefer an absolute ``approval_url`` when a newer identity sends one. Otherwise
    join the public issuer to ``fallback_path`` (it carries the signed token the
    current page requires). If neither field is present, build
    ``{issuer}/oauth/mcp/approval/{id}``.
    """
    raw = str(approval_url or '').strip()
    if _is_absolute_http_url(raw):
        return raw
    origin = _public_identity_origin()
    path = _safe_fallback_path(fallback_path)
    if origin and path:
        return f'{origin}{path}'
    approval_id = str(approval_id or '').strip()
    if origin and approval_id:
        return f'{origin}{APPROVAL_PAGE_PATH.format(approval_id=approval_id)}'
    return approval_settings_url(approval_id or None)


def _expires_text(raw: object) -> str:
    if raw is None or isinstance(raw, bool):
        return ''
    text = str(raw).strip()
    if not text or any(ch in text for ch in '\r\n'):
        return ''
    return text[:80]


def remember_approval(
    approval_id: str,
    payload: dict[str, Any],
    *,
    expires_at: str = '',
    approval_url: str = '',
) -> None:
    """Cache the binding so ``ai_get_approval`` can read status without re-running the tool."""
    from django.core.cache import cache

    approval_id = str(approval_id or '').strip()
    binding = approval_binding_from_payload(payload)
    if not approval_id or binding is None:
        return
    cache.set(
        f'{_APPROVAL_CACHE_PREFIX}{approval_id}',
        {
            'agent_id': binding['agent_id'],
            'company_id': binding['company_id'],
            'binding': binding,
            'service': binding['service'],
            'action': binding['action'],
            'expires_at': _expires_text(expires_at),
            'approval_url': str(approval_url or '').strip(),
        },
        _APPROVAL_CACHE_SECONDS,
    )


def recall_approval(approval_id: str) -> dict[str, Any] | None:
    from django.core.cache import cache

    approval_id = str(approval_id or '').strip()
    if not approval_id:
        return None
    row = cache.get(f'{_APPROVAL_CACHE_PREFIX}{approval_id}')
    return row if isinstance(row, dict) else None


def create_approval_request(payload: dict[str, Any], *, is_destructive: bool = False) -> dict[str, Any] | None:
    _approval_create_error.set('')
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin:
        _set_create_error(CREATE_ERROR_NOT_CONFIGURED)
        return None
    if binding is None:
        _set_create_error(CREATE_ERROR_INVALID)
        return None
    url = f'{origin.rstrip("/")}{APPROVAL_REQUESTS_PATH}'
    # Binding (agent, company, service, action, arguments_hash) is only in the signed assertion header.
    # Never forward tool arguments, paths, methods, or client summaries in the JSON body.
    body: dict[str, Any] = {'is_destructive': bool(is_destructive)}
    ctx = _assertion_context(payload)
    if ctx.blocked_assertion:
        logger.warning('MCP approval create skipped: blocked assertion (setup or global binding)')
        _set_create_error(CREATE_ERROR_BLOCKED)
        return None
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        logger.warning('MCP approval create skipped: signing not configured')
        _set_create_error(CREATE_ERROR_SIGNING)
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
        _set_create_error(CREATE_ERROR_UNREACHABLE)
        return None
    if response.status_code >= 500:
        logger.warning('MCP approval create rejected: %s', response.status_code)
        _set_create_error(CREATE_ERROR_UNREACHABLE)
        return None
    if response.status_code >= 400:
        logger.warning('MCP approval create rejected: %s', response.status_code)
        _set_create_error(CREATE_ERROR_REJECTED)
        return None
    try:
        data = response.json()
    except ValueError:
        _set_create_error(CREATE_ERROR_INVALID)
        return None
    if not isinstance(data, dict) or not data.get('id'):
        _set_create_error(CREATE_ERROR_INVALID)
        return None
    approval_id = str(data['id'])
    expires_at = _expires_text(data.get('expires_at'))
    fallback_path = _safe_fallback_path(str(data.get('fallback_path') or ''))
    page_url = resolve_approval_url(
        approval_id,
        approval_url=str(data.get('approval_url') or ''),
        fallback_path=fallback_path,
    )
    if expires_at:
        payload['approval_expires_at'] = expires_at
    if page_url:
        payload['approval_url_field'] = page_url
    if fallback_path:
        payload['approval_fallback_path'] = fallback_path
    return {
        'id': approval_id,
        'status': str(data.get('status') or 'pending'),
        'expires_at': expires_at,
        'approval_url': page_url,
        'fallback_path': fallback_path,
    }


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
    raw_id = str(data.get('id') or '').strip()
    approval_id = raw_id or None
    expires_at = _expires_text(data.get('expires_at'))
    if expires_at:
        payload['approval_expires_at'] = expires_at
    raw_url = str(data.get('approval_url') or '').strip()
    if raw_url:
        payload['approval_url_field'] = raw_url
    fallback_path = _safe_fallback_path(str(data.get('fallback_path') or ''))
    if fallback_path:
        payload['approval_fallback_path'] = fallback_path
    # Bind pending and approved rows by id so we never create a duplicate when one already exists.
    if status not in {'approved', 'pending'}:
        approval_id = None
    return status or None, approval_id


def _already_consumed_body(response: requests.Response) -> bool:
    """Identity consume returns 409 ``consumed: false`` when the row is already executed."""
    if response.status_code != 409:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    return (
        isinstance(data, dict)
        and data.get('consumed') is False
        and data.get('error') == 'Approval already consumed.'
    )


def consume_approval_detail(approval_id: str, payload: dict[str, Any]) -> ConsumeResult:
    origin = _identity_origin()
    binding = approval_binding_from_payload(payload)
    if not origin or binding is None or not approval_id:
        return ConsumeResult(False)
    url = f'{origin.rstrip("/")}{APPROVAL_CONSUME_PATH}'
    ctx = _assertion_context(payload)
    if ctx.blocked_assertion:
        return ConsumeResult(False)
    try:
        headers = _approval_headers(binding, ctx=ctx)
    except InternalAssertionError:
        return ConsumeResult(False)
    try:
        response = requests.post(
            url,
            json={'approval_id': approval_id},
            headers=headers,
            timeout=5,
        )
    except requests.RequestException:
        return ConsumeResult(False)
    if response.status_code >= 400:
        return ConsumeResult(
            False,
            status_code=response.status_code,
            already_consumed=_already_consumed_body(response),
        )
    try:
        data = response.json()
    except ValueError:
        return ConsumeResult(False, status_code=response.status_code)
    consumed = isinstance(data, dict) and data.get('consumed') is True
    return ConsumeResult(consumed, status_code=response.status_code)


def consume_approval(approval_id: str, payload: dict[str, Any]) -> bool:
    return consume_approval_detail(approval_id, payload).consumed


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
    id_conn = identity_connection_id(connection_id)
    body: dict[str, Any] = {
        'approval_id': approval_id,
        'decision': decision,
        'connection_id': id_conn,
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
    id_conn = identity_connection_id(connection_id)
    if not id_conn or not agent_id or not service or not action or not arguments_hash:
        return False
    if agent_is_revoked(agent_id, company_id):
        return False
    ag = _agent_claims_from_payload(payload)
    expected_gv, expected_cbv = _expected_versions_from_agent_claims(ag)
    expected_gcid = parse_global_company_id(ag.get('global_company_id'))
    ctx = _assertion_context(payload)
    if ctx.blocked_assertion:
        return False
    global_delegated = ctx.is_global_delegated
    if global_delegated:
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
        'connection_id': id_conn,
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

    version_mismatch = resp_gv != expected_gv or resp_cbv != expected_cbv
    if global_delegated:
        # Global delegated: echo canonical global id and both nonnegative ints exactly.
        if resp_gcid is None or expected_gcid is None or resp_gcid != expected_gcid:
            return False
        if resp_gv is None or resp_cbv is None:
            return False
        if version_mismatch:
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
        id_conn = identity_connection_id(connection_id)
        if not id_conn:
            return False
        response = requests.post(
            url,
            json={'connection_id': id_conn},
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
    if approval_id:
        payload['approval_id'] = approval_id
    if status == 'approved' and approval_id:
        return 'approved'
    if status == 'pending':
        return 'pending'
    if status == 'denied':
        return 'denied'
    if status == 'expired':
        return 'expired'
    return None


def elicitation_wait_seconds() -> float:
    raw = getattr(settings, 'MCP_APPROVAL_URL_ELICITATION_WAIT_SECONDS', 20)
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return 20.0


def poll_approval_state(
    payload: dict[str, Any],
    *,
    timeout_seconds: float,
    interval_seconds: float = 1.0,
    sleep: Any = time.sleep,
) -> str | None:
    """Poll Identity until the row is approved, denied, or expired, or the timeout elapses."""
    timeout = max(0.0, float(timeout_seconds))
    interval = max(0.05, float(interval_seconds))
    deadline = time.monotonic() + timeout
    while True:
        state = approval_state(payload)
        if state in {'approved', 'denied', 'expired'}:
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return state
        sleep(min(interval, remaining))


def approval_status_for_agent(approval_id: str, agent_claims: dict[str, Any]) -> dict[str, Any]:
    """Read one cached approval for this agent. Does not consume the grant."""
    from apps.connector import mcp_approval_copy as copy

    approval_id = str(approval_id or '').strip()
    if not approval_id or len(approval_id) > 80 or any(ch.isspace() for ch in approval_id):
        return {
            'status': 'unknown',
            'message': 'Pass the approval_id from the pending tool result.',
        }
    row = recall_approval(approval_id)
    agent_id = str(agent_claims.get('agent_id') or '').strip()
    company_id = strict_numeric_company_id(agent_claims.get('company_id'))
    if (
        row is None
        or str(row.get('agent_id') or '') != agent_id
        or company_id is None
        or row.get('company_id') != company_id
    ):
        return {
            'status': 'unknown',
            'approval_id': approval_id,
            'message': (
                'No approval with that id is waiting on this connection. '
                'Call the tool again to refresh the request.'
            ),
        }
    binding = row.get('binding') if isinstance(row.get('binding'), dict) else {}
    payload: dict[str, Any] = {**binding, '_agent_claims': agent_claims}
    status, found_id = fetch_approval_state(payload)
    tool_name = str(row.get('action') or '').strip() or 'the tool'
    page_url = resolve_approval_url(
        approval_id,
        approval_url=str(payload.get('approval_url_field') or row.get('approval_url') or ''),
        fallback_path=str(payload.get('approval_fallback_path') or ''),
    )
    expires_at = _expires_text(payload.get('approval_expires_at') or row.get('expires_at')) or None
    resolved_id = found_id or approval_id
    if status in {'pending', 'approved', 'denied', 'expired'}:
        body: dict[str, Any] = {
            'status': status,
            'approval_id': resolved_id,
            'expires_at': expires_at,
            'approval_url': page_url,
            'tool': tool_name,
        }
        if status == 'pending':
            body['instruction'] = copy.pending_agent_instruction(tool_name=tool_name)
        elif status == 'approved':
            body['instruction'] = copy.approved_retry_instruction(tool_name=tool_name)
        elif status == 'denied':
            body['message'] = copy.after_deny_text(tool_name=tool_name)
        else:
            body['message'] = copy.expired_text()
        return body
    return {
        'status': 'unknown',
        'approval_id': approval_id,
        'approval_url': page_url,
        'expires_at': expires_at,
        'message': (
            'Approval status could not be read. Call the original tool again, '
            'or try ai_get_approval shortly.'
        ),
    }


def approval_consume(approval_id: str, payload: dict[str, Any] | None = None) -> bool:
    return consume_approval(approval_id, payload or {})


def approval_consume_detail(approval_id: str, payload: dict[str, Any] | None = None) -> ConsumeResult:
    return consume_approval_detail(approval_id, payload or {})
