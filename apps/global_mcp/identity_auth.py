"""Verify identity-global access tokens on dashboard APIs.

These are RS256 JWTs issued by identity-global (aud typically shellui), not the
MCP access tokens or saas API tokens this service mints. Each view must scope
rows to the verified subject.
"""

from __future__ import annotations

import logging

import jwt
from django.conf import settings
from rest_framework import authentication, exceptions

from apps.global_mcp.oidc import _jwks

logger = logging.getLogger(__name__)


class GlobalIdentityUser:
    """Authenticated identity-global account. ``sub`` is the only authorization key."""

    def __init__(self, claims: dict):
        self.sub = str(claims.get('sub') or '').strip()
        self.email = str(claims.get('email') or '').strip()
        self.claims = claims
        self.is_authenticated = True

    def __str__(self) -> str:
        return self.sub


def identity_audience() -> str:
    return str(getattr(settings, 'GLOBAL_IDENTITY_AUDIENCE', '') or '').strip() or 'shellui'


def decode_identity_access_token(raw: str) -> dict:
    """Decode an identity-global access token with the pinned or fetched JWKS."""
    if not raw or raw.count('.') != 2:
        raise jwt.InvalidTokenError('Token is not a JWT.')
    header = jwt.get_unverified_header(raw)
    kid = header.get('kid')
    key = None
    for jwk in _jwks().get('keys') or []:
        if kid and jwk.get('kid') != kid:
            continue
        key = jwt.PyJWK.from_dict(jwk).key
        break
    if key is None:
        raise jwt.InvalidTokenError('identity-global signing key was not found.')
    issuer = str(getattr(settings, 'GLOBAL_IDENTITY_ISSUER', '') or '').strip().rstrip('/') or None
    audience = identity_audience()
    options = {'require': ['exp', 'sub']}
    kwargs: dict = {'algorithms': ['RS256'], 'options': options}
    if audience:
        kwargs['audience'] = audience
    if issuer:
        kwargs['issuer'] = issuer
    claims = jwt.decode(raw, key=key, **kwargs)
    token_type = str(claims.get('token_type') or '').strip()
    if token_type in {'mcp_access', 'saas_api', 'agent_access'}:
        raise jwt.InvalidTokenError('Token is not an identity-global access token.')
    if not str(claims.get('sub') or '').strip():
        raise jwt.InvalidTokenError('Token is missing a subject.')
    return claims


class GlobalIdentityAuthentication(authentication.BaseAuthentication):
    """Bearer JWT from identity-global, used by the dashboard session."""

    keyword = 'Bearer'

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode('utf-8')
        if not header:
            return None
        parts = header.split()
        if len(parts) == 0:
            return None
        if parts[0] != self.keyword or len(parts) != 2:
            return None
        try:
            claims = decode_identity_access_token(parts[1])
        except jwt.ExpiredSignatureError as exc:
            raise exceptions.AuthenticationFailed('Token has expired.') from exc
        except jwt.PyJWTError as exc:
            logger.info('global_identity_auth_failed reason=%s', type(exc).__name__)
            raise exceptions.AuthenticationFailed('The access token is not valid.') from exc
        return (GlobalIdentityUser(claims), parts[1])

    def authenticate_header(self, request):
        return 'Bearer realm="shellui", error="invalid_token"'
