"""RFC 8628 device login for global MCP.

Mirrors identity-service ``apps/agents/oauth_device.py``. Sign-in is identity-global
through ``oidc``. Consent is the same page and the same GlobalAgent setup as the
browser flow. Device codes and user codes are stored as hashes and work once.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.db import transaction
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_POST

from apps.global_mcp import oidc
from apps.global_mcp.codes import hash_code
from apps.global_mcp.copy import DOCS_URL
from apps.global_mcp.models import GlobalAgent, GlobalAgentTokenAudit, McpDeviceAuthorization, McpOAuthClient
from apps.global_mcp.resources import issuer, mcp_resource

USER_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
USER_CODE_LENGTH = 8
SLOW_DOWN_STEP = 5
MAX_POLL_INTERVAL = 300
DEVICE_CODE_LIFETIME_SECONDS = 600
DEVICE_POLL_INTERVAL_SECONDS = 5
DEVICE_CODE_REQUESTS_PER_HOUR = 30
USER_CODE_ATTEMPTS_PER_TEN_MINUTES = 30

_NO_STORE = {'Cache-Control': 'no-store', 'Pragma': 'no-cache'}


def _client_ip(request: HttpRequest) -> str:
    forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
    return forwarded or (request.META.get('REMOTE_ADDR') or 'unknown')


def _over_limit(key: str, limit: int, window: int) -> bool:
    count = int(cache.get(key) or 0)
    if count >= limit:
        return True
    cache.set(key, count + 1, window)
    return False


def _base_url(request: HttpRequest) -> str:
    return issuer() or request.build_absolute_uri('/').rstrip('/')


def new_user_code() -> str:
    raw = ''.join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))
    return f'{raw[:4]}-{raw[4:]}'


def normalize_user_code(value: str) -> str:
    return ''.join(ch for ch in (value or '').upper() if ch.isalnum())


def hash_user_code(value: str) -> str:
    return hash_code(normalize_user_code(value))


@csrf_exempt
@require_POST
def device_authorization(request: HttpRequest):
    """POST /oauth/mcp/device/code. Public clients identify with client_id."""
    from apps.global_mcp.oauth_views import _oauth_ready, _token_body

    if not _oauth_ready():
        return JsonResponse({}, status=404)
    if _over_limit(f'global_mcp:device_code:{_client_ip(request)}', DEVICE_CODE_REQUESTS_PER_HOUR, 3600):
        return JsonResponse({'error': 'slow_down'}, status=429, headers=_NO_STORE)
    body = _token_body(request)
    client_id = str(body.get('client_id') or '').strip()
    if not client_id:
        return JsonResponse({'error': 'invalid_request', 'error_description': 'client_id is required.'}, status=400)
    client = McpOAuthClient.objects.filter(client_id=client_id).first()
    if client is None:
        return JsonResponse({'error': 'invalid_client'}, status=401)
    scope = str(body.get('scope') or 'mcp').strip()
    if scope and set(scope.split()) - {'mcp'}:
        return JsonResponse({'error': 'invalid_scope'}, status=400)
    resource = str(body.get('resource') or '').strip()
    if resource and resource.rstrip('/') != mcp_resource(request).rstrip('/'):
        return JsonResponse({'error': 'invalid_target'}, status=400)
    device_code = secrets.token_urlsafe(32)
    for _attempt in range(5):
        user_code = new_user_code()
        if not McpDeviceAuthorization.objects.filter(user_code_hash=hash_user_code(user_code)).exists():
            break
    McpDeviceAuthorization.objects.create(
        client=client,
        device_code_hash=hash_code(device_code),
        user_code_hash=hash_user_code(user_code),
        scope='mcp',
        poll_interval=DEVICE_POLL_INTERVAL_SECONDS,
        expires_at=timezone.now() + timedelta(seconds=DEVICE_CODE_LIFETIME_SECONDS),
    )
    verification_uri = f'{_base_url(request)}/oauth/mcp/device'
    return JsonResponse(
        {
            'device_code': device_code,
            'user_code': user_code,
            'verification_uri': verification_uri,
            'verification_uri_complete': f'{verification_uri}?user_code={user_code}',
            'expires_in': DEVICE_CODE_LIFETIME_SECONDS,
            'interval': DEVICE_POLL_INTERVAL_SECONDS,
        },
        headers=_NO_STORE,
    )


def _expire_if_due(row: McpDeviceAuthorization) -> bool:
    if row.expires_at > timezone.now():
        return False
    if row.status in {McpDeviceAuthorization.STATUS_PENDING, McpDeviceAuthorization.STATUS_APPROVED}:
        if row.status == McpDeviceAuthorization.STATUS_APPROVED and row.agent_id:
            GlobalAgent.objects.filter(pk=row.agent_id, revoked_at__isnull=True).update(revoked_at=timezone.now())
        row.status = McpDeviceAuthorization.STATUS_EXPIRED
        row.save(update_fields=['status'])
    return True


def _pending_for_session(request: HttpRequest) -> McpDeviceAuthorization | None:
    from apps.global_mcp.oauth_views import _SESSION_DEVICE

    raw = request.session.get(_SESSION_DEVICE) or ''
    try:
        row = McpDeviceAuthorization.objects.select_related('client').get(pk=raw)
    except (McpDeviceAuthorization.DoesNotExist, ValidationError, ValueError, TypeError):
        return None
    if row.status != McpDeviceAuthorization.STATUS_PENDING or _expire_if_due(row):
        return None
    return row


def _code_page(request: HttpRequest, *, error: str = '', status: int = 200, user_code: str = '') -> HttpResponse:
    return render(
        request,
        'global_mcp/device_code.html',
        {'error': error, 'docs_url': DOCS_URL, 'user_code': user_code},
        status=status,
    )


def _lookup_code(request: HttpRequest, raw: str) -> HttpResponse | None:
    """Store the matching device login in the session. Return a page on error."""
    from apps.global_mcp.oauth_views import _SESSION_DEVICE

    if _over_limit(f'global_mcp:device_entry:{_client_ip(request)}', USER_CODE_ATTEMPTS_PER_TEN_MINUTES, 600):
        return _code_page(request, error='Too many attempts. Wait a few minutes and try again.', status=429)
    normalized = normalize_user_code(raw)
    if len(normalized) != USER_CODE_LENGTH:
        return _code_page(request, error='Enter the eight letters or digits your agent showed.', status=400, user_code=raw)
    row = McpDeviceAuthorization.objects.filter(user_code_hash=hash_code(normalized)).first()
    if row is None or row.status != McpDeviceAuthorization.STATUS_PENDING or _expire_if_due(row):
        return _code_page(
            request,
            error='This code is not valid or has expired. Start the connection again from your agent.',
            status=400,
            user_code=raw,
        )
    request.session[_SESSION_DEVICE] = str(row.id)
    return None


@require_http_methods(['GET', 'POST'])
def device_verify(request: HttpRequest):
    """GET/POST /oauth/mcp/device. Code entry, sign-in, then consent."""
    from apps.global_mcp.oauth_views import (
        _SESSION_DEVICE,
        _SESSION_USER,
        _message,
        _oauth_ready,
        consent_context,
        create_agent_from_consent,
    )

    if not _oauth_ready():
        return JsonResponse({}, status=404)
    if request.method == 'GET' and request.GET.get('user_code'):
        page = _lookup_code(request, request.GET['user_code'])
        if page is not None:
            return page
        return HttpResponseRedirect('/oauth/mcp/device')
    if request.method == 'POST' and 'decision' not in request.POST:
        page = _lookup_code(request, request.POST.get('user_code') or '')
        if page is not None:
            return page
        return HttpResponseRedirect('/oauth/mcp/device')

    row = _pending_for_session(request)
    if row is None:
        if request.method == 'POST':
            return _message(request, 'This device login is no longer pending. Start again from your agent.', status=400, title='Device login expired')
        return _code_page(request)
    user = request.session.get(_SESSION_USER)
    if not isinstance(user, dict) or not user.get('sub'):
        if request.method == 'POST':
            return _message(request, 'Sign in again to connect this agent.', status=400, title='Sign in again')
        try:
            return HttpResponseRedirect(oidc.begin(device=row))
        except Exception:
            return _message(request, 'Sign-in is not available right now. Try again later.', status=503, title='Sign-in unavailable')
    if request.method == 'GET':
        return render(
            request,
            'global_mcp/consent.html',
            consent_context(row.client, user, hidden_name='device', hidden_value=row.id),
        )
    if str(request.POST.get('device') or '') != str(row.id):
        return _message(request, 'This device login does not match your session. Start again from your agent.', status=400, title='Session mismatch')
    decision = request.POST.get('decision') or ''
    with transaction.atomic():
        locked = McpDeviceAuthorization.objects.select_for_update().select_related('client').get(pk=row.pk)
        if locked.status != McpDeviceAuthorization.STATUS_PENDING or _expire_if_due(locked):
            return _message(request, 'This device login is no longer pending. Start again from your agent.', status=400, title='Device login expired')
        locked.owner_sub = user['sub']
        locked.decided_at = timezone.now()
        if decision != 'allow':
            locked.status = McpDeviceAuthorization.STATUS_DENIED
            locked.save(update_fields=['status', 'owner_sub', 'decided_at'])
            request.session.pop(_SESSION_DEVICE, None)
            return _message(request, 'Access denied. Your agent will not connect.', status=200, title='Access denied')
        locked.agent = create_agent_from_consent(request, locked.client, user)
        locked.status = McpDeviceAuthorization.STATUS_APPROVED
        locked.save(update_fields=['status', 'owner_sub', 'decided_at', 'agent'])
    request.session.pop(_SESSION_DEVICE, None)
    return _message(request, 'Approved. Return to your agent. It connects on its next check.', status=200, title='Agent approved')


def _error(code: str, status: int = 400, description: str = '') -> JsonResponse:
    body = {'error': code}
    if description:
        body['error_description'] = description
    return JsonResponse(body, status=status, headers=_NO_STORE)


def device_token(body: dict) -> JsonResponse:
    """Token endpoint branch for urn:ietf:params:oauth:grant-type:device_code."""
    from apps.global_mcp.oauth_views import _new_refresh, _token_response
    from apps.global_mcp.tokens import issue_mcp_access_token

    raw = str(body.get('device_code') or '').strip()
    client_id = str(body.get('client_id') or '').strip()
    if not raw or not client_id:
        return _error('invalid_request', description='device_code and client_id are required.')
    client = McpOAuthClient.objects.filter(client_id=client_id).first()
    if client is None:
        return _error('invalid_client', status=401)
    resource = str(body.get('resource') or '').strip()
    if resource and resource.rstrip('/') != mcp_resource().rstrip('/'):
        return _error('invalid_target')
    now = timezone.now()
    with transaction.atomic():
        row = (
            McpDeviceAuthorization.objects.select_for_update(of=('self',))
            .select_related('agent')
            .filter(device_code_hash=hash_code(raw))
            .first()
        )
        if row is None or row.client_id != client.pk:
            return _error('invalid_grant')
        if row.status == McpDeviceAuthorization.STATUS_CONSUMED:
            return _error('invalid_grant', description='This device code was already used.')
        if row.status == McpDeviceAuthorization.STATUS_DENIED:
            return _error('access_denied')
        if row.status == McpDeviceAuthorization.STATUS_EXPIRED or _expire_if_due(row):
            return _error('expired_token')
        if row.last_poll_at is not None and (now - row.last_poll_at).total_seconds() < row.poll_interval:
            row.poll_interval = min(row.poll_interval + SLOW_DOWN_STEP, MAX_POLL_INTERVAL)
            row.last_poll_at = now
            row.save(update_fields=['poll_interval', 'last_poll_at'])
            return _error('slow_down', description=f'Poll at most every {row.poll_interval} seconds.')
        row.last_poll_at = now
        if row.status == McpDeviceAuthorization.STATUS_PENDING:
            row.save(update_fields=['last_poll_at'])
            return _error('authorization_pending')
        agent = row.agent
        if agent is None or not agent.is_active:
            row.status = McpDeviceAuthorization.STATUS_EXPIRED
            row.save(update_fields=['status', 'last_poll_at'])
            return _error('access_denied')
        row.status = McpDeviceAuthorization.STATUS_CONSUMED
        row.consumed_at = now
        row.save(update_fields=['status', 'consumed_at', 'last_poll_at'])
    access, claims = issue_mcp_access_token(agent)
    refresh = _new_refresh(agent)
    GlobalAgentTokenAudit.objects.create(
        event_type=GlobalAgentTokenAudit.EVENT_DEVICE_EXCHANGE,
        global_agent=agent,
        owner_sub=agent.owner_sub,
        jti=claims.get('jti') or '',
        exp=timezone.now() + timedelta(seconds=int(settings.GLOBAL_MCP_ACCESS_TOKEN_TTL_SECONDS)),
        oauth_client_id=client.client_id,
    )
    return _token_response(access, refresh)
