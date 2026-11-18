"""Confidential OIDC login against identity-global. The consent page stays on ai-service."""

from __future__ import annotations

import secrets
from datetime import timedelta
from urllib.parse import urlencode

import jwt
import requests
from django.conf import settings
from django.utils import timezone

from apps.global_mcp.models import McpAuthorizationRequest, OidcTransaction
from apps.global_mcp.pkce import new_verifier, s256_challenge


class OidcError(Exception):
    def __init__(self, code: str, description: str = '') -> None:
        super().__init__(description or code)
        self.code = code
        self.description = description


def _identity_public() -> str:
    return str(settings.GLOBAL_IDENTITY_URL or '').rstrip('/')


def _identity_internal() -> str:
    return str(settings.GLOBAL_IDENTITY_INTERNAL_URL or settings.GLOBAL_IDENTITY_URL or '').rstrip('/')


def redirect_uri() -> str:
    explicit = str(settings.GLOBAL_OIDC_REDIRECT_URI or '').strip()
    if explicit:
        return explicit
    base = str(settings.AI_PUBLIC_URL or settings.AI_SERVICE_ISSUER or '').rstrip('/')
    return f'{base}/oauth/mcp/signin/complete'


def begin(authorization: McpAuthorizationRequest) -> str:
    """Return the identity-global authorize URL. No prompt=none: the login page must render."""
    verifier = new_verifier()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(18)
    OidcTransaction.objects.create(
        state=state,
        nonce=nonce,
        code_verifier=verifier,
        authorization_request=authorization,
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    query = urlencode(
        {
            'response_type': 'code',
            'client_id': settings.GLOBAL_OIDC_CLIENT_ID,
            'redirect_uri': redirect_uri(),
            'scope': 'openid email profile',
            'state': state,
            'nonce': nonce,
            'code_challenge': s256_challenge(verifier),
            'code_challenge_method': 'S256',
        }
    )
    return f'{_identity_public()}/oauth/authorize?{query}'


def complete(state: str, code: str) -> tuple[OidcTransaction, dict]:
    row = OidcTransaction.objects.select_related('authorization_request').filter(state=state).first()
    if row is None or row.consumed_at is not None or row.expires_at <= timezone.now():
        raise OidcError('invalid_state', 'Sign-in state is not valid.')
    token = _exchange(code, row.code_verifier)
    claims = _verify_id_token(str(token.get('id_token') or ''), nonce=row.nonce)
    access = str(token.get('access_token') or '')
    claims['access_token'] = access
    row.consumed_at = timezone.now()
    row.save(update_fields=['consumed_at'])
    return row, claims


def _exchange(code: str, verifier: str) -> dict:
    response = requests.post(
        f'{_identity_internal()}/oauth/token',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri(),
            'client_id': settings.GLOBAL_OIDC_CLIENT_ID,
            'client_secret': settings.GLOBAL_OIDC_CLIENT_SECRET,
            'code_verifier': verifier,
        },
        timeout=10,
    )
    try:
        payload = response.json()
    except ValueError as exc:
        raise OidcError('server_error', 'identity-global token response was not JSON.') from exc
    if response.status_code >= 400:
        raise OidcError(str(payload.get('error') or 'invalid_grant'), str(payload.get('error_description') or ''))
    return payload if isinstance(payload, dict) else {}


def _jwks() -> dict:
    document = getattr(settings, 'GLOBAL_IDENTITY_JWKS_DOCUMENT', None)
    if isinstance(document, dict) and document.get('keys'):
        return document
    url = str(settings.GLOBAL_IDENTITY_JWKS_URL or '').strip()
    if not url:
        raise OidcError('server_error', 'identity-global JWKS is not configured.')
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise OidcError('server_error', 'identity-global JWKS is not a document.')
    return body


def _verify_id_token(token: str, *, nonce: str) -> dict:
    if not token:
        raise OidcError('invalid_grant', 'identity-global did not return an id token.')
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        key = None
        for jwk in _jwks().get('keys') or []:
            if kid and jwk.get('kid') != kid:
                continue
            key = jwt.PyJWK.from_dict(jwk).key
            break
        if key is None:
            raise OidcError('invalid_grant', 'identity-global signing key was not found.')
        claims = jwt.decode(
            token,
            key=key,
            algorithms=['RS256'],
            audience=settings.GLOBAL_OIDC_CLIENT_ID,
            issuer=settings.GLOBAL_IDENTITY_ISSUER or None,
            options={'require': ['exp', 'iat', 'iss', 'aud', 'sub']},
        )
    except OidcError:
        raise
    except jwt.PyJWTError as exc:
        raise OidcError('invalid_grant', 'id token is not valid.') from exc
    if nonce and claims.get('nonce') != nonce:
        raise OidcError('invalid_grant', 'id token nonce does not match.')
    return claims
