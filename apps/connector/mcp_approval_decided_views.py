"""Identity → ai-service wake when an MCP approval is decided."""

from __future__ import annotations

import logging

import jwt
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from apps.authapi.jwks_client import get_jwks_client
from apps.connector.mcp_approval_events import publish_approval_decision

logger = logging.getLogger(__name__)

APPROVAL_DECIDED_AUDIENCE = 'shellui-mcp-approval-decided'
APPROVAL_DECIDED_SCOPE = 'mcp.approval.decided'


@method_decorator(csrf_exempt, name='dispatch')
class McpApprovalDecidedView(View):
    """``POST /internal/mcp-approval-decided`` — Identity notifies after Approve/Deny."""

    http_method_names = ['post']

    def post(self, request: HttpRequest) -> HttpResponse:
        claims = _verify_bearer(request)
        if claims is None:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        try:
            import json

            body = json.loads(request.body.decode('utf-8') or '{}')
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            body = {}
        if not isinstance(body, dict):
            body = {}
        approval_id = str(body.get('approval_id') or claims.get('approval_id') or '').strip()
        status = str(body.get('status') or claims.get('status') or '').strip().lower()
        if not approval_id or status not in {'approved', 'denied'}:
            return JsonResponse({'error': 'invalid_body'}, status=400)
        claim_id = str(claims.get('approval_id') or '').strip()
        claim_status = str(claims.get('status') or '').strip().lower()
        if claim_id and claim_id != approval_id:
            return JsonResponse({'error': 'mismatch'}, status=400)
        if claim_status and claim_status != status:
            return JsonResponse({'error': 'mismatch'}, status=400)
        publish_approval_decision(approval_id, status)
        return HttpResponse(status=204)


def _verify_bearer(request: HttpRequest) -> dict | None:
    auth = str(request.headers.get('Authorization') or '').strip()
    if not auth.lower().startswith('bearer '):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    algorithms = list(getattr(settings, 'JWT_ALGORITHMS', ['RS256']))
    options = {
        'require': ['exp', 'iat', 'aud', 'iss', 'scope', 'approval_id', 'status'],
        'verify_aud': True,
        'verify_iss': bool(settings.IDENTITY_ISSUER),
    }
    decode_kwargs: dict = {
        'algorithms': algorithms,
        'options': options,
        'audience': APPROVAL_DECIDED_AUDIENCE,
    }
    if settings.IDENTITY_ISSUER:
        decode_kwargs['issuer'] = settings.IDENTITY_ISSUER
    try:
        signing_key = get_jwks_client().get_signing_key(token)
        if signing_key is None:
            raise jwt.InvalidTokenError('no signing key')
        payload = jwt.decode(token, key=signing_key.key, **decode_kwargs)
    except jwt.InvalidTokenError:
        secret = getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None)
        allow_hs256 = bool(secret) and (
            settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False)
        )
        if not allow_hs256:
            return None
        try:
            payload = jwt.decode(
                token,
                key=secret,
                algorithms=['HS256'],
                audience=APPROVAL_DECIDED_AUDIENCE,
                issuer=settings.IDENTITY_ISSUER or None,
                options=options,
            )
        except jwt.InvalidTokenError:
            return None
    except Exception:
        logger.warning('MCP approval decided auth failed', exc_info=True)
        return None
    if str(payload.get('scope') or '') != APPROVAL_DECIDED_SCOPE:
        return None
    return payload if isinstance(payload, dict) else None
