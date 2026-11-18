"""Global MCP OAuth authorization server. Sign-in is identity-global. Consent is here."""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import timedelta
from urllib.parse import urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.db import transaction
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from apps.global_mcp import oidc
from apps.global_mcp.codes import hash_code, hash_token, issue_code
from apps.global_mcp.copy import DOCS_URL, REGION_ONLY_MESSAGE, STAFF_MESSAGE, TERMS_MESSAGE
from apps.global_mcp.eligibility import staff_refused, terms_accepted
from apps.global_mcp.models import (
    GlobalAgent,
    GlobalRefreshToken,
    McpAuthorizationCode,
    McpAuthorizationRequest,
    McpOAuthClient,
)
from apps.global_mcp.pkce import PkceError, parse_client_pkce, verify_client_pkce
from apps.global_mcp.redirects import normalize_mcp_redirect_uris, validate_mcp_redirect_uri
from apps.global_mcp.resources import issuer, mcp_resource
from apps.global_mcp.saas_client import fetch_me
from apps.global_mcp.tokens import issue_mcp_access_token

_SESSION_USER = 'global_mcp_user'
_SESSION_REQUEST = 'global_mcp_request'


def _oauth_ready() -> bool:
    return bool(settings.AI_SERVICE_ISSUER and settings.GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE)


def authorization_server_metadata(request: HttpRequest):
    if not _oauth_ready():
        return JsonResponse({}, status=404)
    base = issuer() or request.build_absolute_uri('/').rstrip('/')
    return JsonResponse(
        {
            'issuer': base,
            'authorization_endpoint': f'{base}/oauth/mcp/authorize',
            'token_endpoint': f'{base}/oauth/mcp/token',
            'registration_endpoint': f'{base}/oauth/mcp/register',
            'jwks_uri': f'{base}/.well-known/jwks.json',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none'],
            'scopes_supported': ['mcp'],
            'resource_indicators_supported': True,
        }
    )


def protected_resource_metadata(request: HttpRequest):
    base = issuer() or request.build_absolute_uri('/').rstrip('/')
    resource = mcp_resource(request)
    return JsonResponse(
        {
            'resource': resource,
            'authorization_servers': [base],
            'scopes_supported': ['mcp'],
            'bearer_methods_supported': ['header'],
        }
    )


def _client_ip(request: HttpRequest) -> str:
    forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
    return forwarded or (request.META.get('REMOTE_ADDR') or '')


@csrf_exempt
@require_POST
def mcp_register(request: HttpRequest):
    if not _oauth_ready():
        return JsonResponse({}, status=404)
    if not getattr(settings, 'MCP_DYNAMIC_CLIENT_REGISTRATION', True):
        return JsonResponse({'error': 'registration_disabled'}, status=403)
    from django.core.cache import cache

    ip = _client_ip(request) or 'unknown'
    key = f'global_mcp:dcr:{ip}'
    count = int(cache.get(key) or 0)
    if count >= 30:
        return JsonResponse({'error': 'slow_down'}, status=429)
    cache.set(key, count + 1, 3600)
    try:
        body = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'invalid_json'}, status=400)
    redirect_uris, error = normalize_mcp_redirect_uris(request, body.get('redirect_uris') or [])
    if error or not redirect_uris:
        return JsonResponse({'error': error or 'invalid_redirect_uris'}, status=400)
    client_id = secrets.token_urlsafe(24)
    McpOAuthClient.objects.create(
        client_id=client_id,
        client_name=str(body.get('client_name') or '')[:255],
        redirect_uris=redirect_uris,
    )
    return JsonResponse(
        {
            'client_id': client_id,
            'client_name': body.get('client_name') or '',
            'redirect_uris': redirect_uris,
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none',
        },
        status=201,
    )


def _redirect_error(redirect_uri: str, error: str, state: str) -> HttpResponseRedirect:
    parts = urlsplit(redirect_uri)
    params = {'error': error}
    if state:
        params['state'] = state
    return HttpResponseRedirect(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), '')))


@require_GET
def mcp_authorize(request: HttpRequest):
    if not _oauth_ready():
        return JsonResponse({}, status=404)
    client_id = (request.GET.get('client_id') or '').strip()
    redirect_uri = (request.GET.get('redirect_uri') or '').strip()
    client = McpOAuthClient.objects.filter(client_id=client_id).first()
    canonical, error = validate_mcp_redirect_uri(request, redirect_uri)
    if client is None or error or not canonical or canonical not in (client.redirect_uris or []):
        return JsonResponse({'error': 'invalid_request', 'error_description': error or 'invalid client'}, status=400)
    if request.GET.get('response_type') not in {None, '', 'code'}:
        return _redirect_error(canonical, 'unsupported_response_type', request.GET.get('state') or '')
    resource = (request.GET.get('resource') or '').strip()
    expected = mcp_resource(request)
    if resource and resource.rstrip('/') != expected.rstrip('/'):
        return _redirect_error(canonical, 'invalid_target', request.GET.get('state') or '')
    try:
        challenge = parse_client_pkce(
            request.GET.get('code_challenge'),
            request.GET.get('code_challenge_method') or 'S256',
            required=True,
        )
    except PkceError as exc:
        return _redirect_error(canonical, exc.error_code, request.GET.get('state') or '')
    pending = McpAuthorizationRequest.objects.create(
        client=client,
        redirect_uri=canonical,
        state=(request.GET.get('state') or '')[:500],
        code_challenge=challenge,
        resource=resource,
        scope=(request.GET.get('scope') or 'mcp')[:200],
        expires_at=timezone.now() + timedelta(minutes=15),
    )
    request.session[_SESSION_REQUEST] = str(pending.id)
    user = request.session.get(_SESSION_USER)
    if isinstance(user, dict) and user.get('sub'):
        return HttpResponseRedirect(f'/oauth/mcp/consent?request={pending.id}')
    try:
        target = oidc.begin(pending)
    except Exception:
        return _redirect_error(canonical, 'server_error', pending.state)
    return HttpResponseRedirect(target)


@require_GET
def signin_complete(request: HttpRequest):
    error = (request.GET.get('error') or '').strip()
    if error:
        return _message(request, REGION_ONLY_MESSAGE, status=403)
    state = (request.GET.get('state') or '').strip()
    code = (request.GET.get('code') or '').strip()
    if not state or not code:
        return _message(request, 'Sign-in did not finish.', status=400)
    try:
        row, claims = oidc.complete(state, code)
    except oidc.OidcError as exc:
        return _message(request, exc.description or 'Sign-in failed.', status=400)
    access = str(claims.get('access_token') or '')
    profile = fetch_me(access)
    if profile is None:
        return _message(request, REGION_ONLY_MESSAGE, status=403)
    if staff_refused(profile.raw, claims):
        return _message(request, STAFF_MESSAGE, status=403)
    if not terms_accepted(profile.raw, claims):
        return _message(request, TERMS_MESSAGE, status=403)
    request.session[_SESSION_USER] = {
        'sub': profile.sub,
        'email': profile.email,
        'name': profile.name,
        'claims': {key: value for key, value in claims.items() if key != 'access_token'},
        'profile': profile.raw,
    }
    request.session[_SESSION_REQUEST] = str(row.authorization_request_id)
    return HttpResponseRedirect(f'/oauth/mcp/consent?request={row.authorization_request_id}')


def _load_request(request: HttpRequest) -> McpAuthorizationRequest | None:
    raw = (request.GET.get('request') or request.POST.get('request') or request.session.get(_SESSION_REQUEST) or '')
    try:
        found = McpAuthorizationRequest.objects.select_related('client').get(pk=raw)
    except (McpAuthorizationRequest.DoesNotExist, ValueError, TypeError):
        return None
    if found.consumed_at is not None or found.expires_at <= timezone.now():
        return None
    return found


@require_http_methods(['GET', 'POST'])
def mcp_consent(request: HttpRequest):
    pending = _load_request(request)
    user = request.session.get(_SESSION_USER)
    if pending is None or not isinstance(user, dict):
        return _message(request, 'Sign in again to connect this agent.', status=400)
    if request.method == 'GET':
        return render(
            request,
            'global_mcp/consent.html',
            {
                'client_name': pending.client.client_name or 'MCP client',
                'request_id': pending.id,
                'email': user.get('email') or '',
                'docs_url': DOCS_URL,
                'region_message': REGION_ONLY_MESSAGE,
            },
        )
    if (request.POST.get('decision') or '') != 'allow':
        pending.consumed_at = timezone.now()
        pending.save(update_fields=['consumed_at'])
        return _redirect_error(pending.redirect_uri, 'access_denied', pending.state)
    name = (request.POST.get('agent_name') or pending.client.client_name or 'MCP agent')[:255]
    access = request.POST.get('access_mode') or GlobalAgent.ACCESS_ASK
    if access not in {GlobalAgent.ACCESS_READ_ONLY, GlobalAgent.ACCESS_ASK, GlobalAgent.ACCESS_FULL}:
        access = GlobalAgent.ACCESS_ASK
    read_level = request.POST.get('read_level') or GlobalAgent.READ_SAFE
    if read_level not in {GlobalAgent.READ_SAFE, GlobalAgent.READ_SENSITIVE}:
        read_level = GlobalAgent.READ_SAFE
    destructive = request.POST.get('allow_destructive') in {'1', 'on', 'true'}
    agent = GlobalAgent.objects.create(
        name=name,
        owner_sub=user['sub'],
        owner_email=user.get('email') or '',
        owner_name=user.get('name') or '',
        oauth_client=pending.client,
        access_mode=access,
        read_level=read_level,
        allow_destructive_without_asking=destructive,
        services_allowed=['saas'],
        setup_flow=True,
        setup_expires_at=timezone.now() + timedelta(minutes=12),
    )
    return _issue_code(pending, agent, user)


def _issue_code(pending: McpAuthorizationRequest, agent: GlobalAgent, user: dict) -> HttpResponseRedirect:
    raw, digest = issue_code()
    stored_claims = dict(user.get('claims') or {}) if isinstance(user.get('claims'), dict) else {}
    stored_claims['terms_accepted'] = True
    stored_claims['is_staff'] = False
    stored_claims['is_superuser'] = False
    stored_claims['is_global_staff'] = False
    McpAuthorizationCode.objects.create(
        code_hash=digest,
        client=pending.client,
        owner_sub=user['sub'],
        owner_email=user.get('email') or '',
        owner_name=user.get('name') or '',
        owner_claims=stored_claims,
        agent=agent,
        redirect_uri=pending.redirect_uri,
        code_challenge=pending.code_challenge,
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    pending.consumed_at = timezone.now()
    pending.save(update_fields=['consumed_at'])
    parts = urlsplit(pending.redirect_uri)
    params = {'code': raw}
    if pending.state:
        params['state'] = pending.state
    joiner = '&' if parts.query else ''
    query = parts.query + joiner + urlencode(params) if parts.query else urlencode(params)
    return HttpResponseRedirect(urlunsplit((parts.scheme, parts.netloc, parts.path, query, '')))


def _token_body(request: HttpRequest) -> dict:
    content = (request.content_type or '').lower()
    if 'application/json' in content:
        try:
            body = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return {}
        return body if isinstance(body, dict) else {}
    return {key: request.POST.get(key) for key in request.POST}


def _token_response(access: str, refresh: str) -> JsonResponse:
    return JsonResponse(
        {
            'access_token': access,
            'token_type': 'Bearer',
            'expires_in': int(settings.GLOBAL_MCP_ACCESS_TOKEN_TTL_SECONDS),
            'refresh_token': refresh,
            'scope': 'mcp',
        },
        headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'},
    )


def _new_refresh(agent: GlobalAgent, family: uuid.UUID | None = None) -> str:
    raw = secrets.token_urlsafe(32)
    GlobalRefreshToken.objects.create(
        agent=agent,
        family_id=family or uuid.uuid4(),
        token_hash=hash_token(raw),
        expires_at=timezone.now() + timedelta(seconds=int(settings.GLOBAL_MCP_REFRESH_TOKEN_TTL_SECONDS)),
    )
    return raw


@csrf_exempt
@require_POST
def mcp_token(request: HttpRequest):
    if not _oauth_ready():
        return JsonResponse({}, status=404)
    body = _token_body(request)
    grant = str(body.get('grant_type') or '')
    if grant == 'refresh_token':
        return _refresh(body)
    if grant != 'authorization_code':
        return JsonResponse({'error': 'unsupported_grant_type'}, status=400)
    client = McpOAuthClient.objects.filter(client_id=str(body.get('client_id') or '').strip()).first()
    if client is None:
        return JsonResponse({'error': 'invalid_client'}, status=401)
    canonical, error = validate_mcp_redirect_uri(request, str(body.get('redirect_uri') or ''))
    if error or not canonical:
        return JsonResponse({'error': 'invalid_grant'}, status=400)
    with transaction.atomic():
        row = (
            McpAuthorizationCode.objects.select_for_update()
            .select_related('agent')
            .filter(code_hash=hash_code(str(body.get('code') or '')), client=client)
            .first()
        )
        if row is None or row.redeemed_at is not None or row.expires_at <= timezone.now():
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        if row.redirect_uri != canonical:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        message, _code = verify_client_pkce(
            code_challenge=row.code_challenge,
            code_verifier=body.get('code_verifier'),
            required=True,
        )
        if message:
            return JsonResponse({'error': 'invalid_grant', 'error_description': message}, status=400)
        if staff_refused(row.owner_claims, row.owner_claims):
            return JsonResponse({'error': 'access_denied', 'error_description': STAFF_MESSAGE}, status=403)
        if not terms_accepted(row.owner_claims, row.owner_claims):
            return JsonResponse({'error': 'access_denied', 'error_description': TERMS_MESSAGE}, status=403)
        if not row.agent.is_active:
            return JsonResponse({'error': 'access_denied'}, status=403)
        row.redeemed_at = timezone.now()
        row.save(update_fields=['redeemed_at'])
        agent = row.agent
    access, _claims = issue_mcp_access_token(agent)
    refresh = _new_refresh(agent)
    from apps.global_mcp.models import GlobalAgentTokenAudit

    GlobalAgentTokenAudit.objects.create(
        event_type=GlobalAgentTokenAudit.EVENT_CODE_EXCHANGE,
        global_agent=agent,
        owner_sub=agent.owner_sub,
        jti=_claims.get('jti') or '',
        exp=timezone.now() + timedelta(seconds=int(settings.GLOBAL_MCP_ACCESS_TOKEN_TTL_SECONDS)),
        oauth_client_id=client.client_id,
    )
    return _token_response(access, refresh)


def _refresh(body: dict) -> JsonResponse:
    raw = str(body.get('refresh_token') or '').strip()
    if not raw:
        return JsonResponse({'error': 'invalid_grant'}, status=400)
    with transaction.atomic():
        row = (
            GlobalRefreshToken.objects.select_for_update()
            .select_related('agent')
            .filter(token_hash=hash_token(raw))
            .first()
        )
        if row is None:
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        if row.rotated_at is not None or row.revoked_at is not None:
            GlobalRefreshToken.objects.filter(family_id=row.family_id, revoked_at__isnull=True).update(
                revoked_at=timezone.now()
            )
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        if row.expires_at <= timezone.now() or not row.agent.is_active:
            row.revoked_at = timezone.now()
            row.save(update_fields=['revoked_at'])
            return JsonResponse({'error': 'invalid_grant'}, status=400)
        row.rotated_at = timezone.now()
        row.save(update_fields=['rotated_at'])
        agent = row.agent
        family = row.family_id
    access, _claims = issue_mcp_access_token(agent)
    refresh = _new_refresh(agent, family)
    return _token_response(access, refresh)


def _message(request: HttpRequest, text: str, *, status: int) -> HttpResponse:
    return render(
        request,
        'global_mcp/message.html',
        {'message': text, 'docs_url': DOCS_URL},
        status=status,
    )


@require_http_methods(['GET', 'POST'])
def approval_page(request: HttpRequest, approval_id):
    from apps.global_mcp.approvals import decide_page
    from apps.global_mcp.models import GlobalMcpApprovalRequest

    user = request.session.get(_SESSION_USER)
    if not isinstance(user, dict) or not user.get('sub'):
        return _message(request, 'Sign in with your Shellui account to decide this approval.', status=401)
    approval = GlobalMcpApprovalRequest.objects.filter(pk=approval_id).first()
    if approval is None or approval.owner_sub != user['sub']:
        return _message(request, 'This approval is not for your account.', status=404)
    if request.method == 'GET':
        return render(
            request,
            'global_mcp/decision.html',
            {
                'approval': approval,
                'summary': approval.short_action_summary or approval.action,
                'destructive': approval.is_destructive,
            },
        )
    allow = (request.POST.get('decision') or '') == 'allow'
    outcome = decide_page(approval, actor_sub=user['sub'], allow=allow)
    label = {
        'approved': 'Approved. Return to the chat.',
        'rejected': 'Denied. Return to the chat.',
        'expired': 'This approval expired.',
        'forbidden': 'This approval is not for your account.',
    }.get(outcome, 'This approval is already decided.')
    return _message(request, label, status=200 if outcome in {'approved', 'rejected'} else 400)
