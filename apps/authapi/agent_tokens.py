"""Decode Shellui MCP agent access tokens issued by identity-service."""

from __future__ import annotations

import jwt
from django.conf import settings
from apps.authapi.jwks_client import get_jwks_client
from apps.connector.mcp_identity import personal_agent_bearer_valid
from apps.connector.mcp_urls import company_audience_matches, company_id_from_resource, normalize_company_resource

from .principal import StoragePrincipal


def _decode_agent_claims(raw_token: str, *, expected_resource: str) -> dict | None:
    expected = normalize_company_resource(expected_resource) or ''
    if not expected:
        return None
    algorithms = list(getattr(settings, 'JWT_ALGORITHMS', ['RS256']))
    options = {
        'require': ['exp', 'sub', 'agent_id', 'aud', 'company_id'],
        'verify_aud': True,
        'verify_iss': bool(settings.IDENTITY_ISSUER),
    }
    decode_kwargs: dict = {'algorithms': algorithms, 'options': options, 'audience': expected}
    if settings.IDENTITY_ISSUER:
        decode_kwargs['issuer'] = settings.IDENTITY_ISSUER

    try:
        signing_key = get_jwks_client().get_signing_key(raw_token)
        if signing_key is not None:
            payload = jwt.decode(raw_token, key=signing_key.key, **decode_kwargs)
            if (
                str(payload.get('sub', '')).startswith('agent:')
                and company_audience_matches(payload, expected)
                and _company_id_matches_resource(payload, expected)
            ):
                return payload
    except jwt.InvalidTokenError:
        pass
    except Exception:
        pass

    secret = getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None)
    allow_hs256 = bool(secret) and (
        settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False)
    )
    if allow_hs256:
        try:
            payload = jwt.decode(
                raw_token,
                key=secret,
                algorithms=['HS256'],
                audience=expected,
                issuer=settings.IDENTITY_ISSUER or None,
                options=options,
            )
            if (
                str(payload.get('sub', '')).startswith('agent:')
                and company_audience_matches(payload, expected)
                and _company_id_matches_resource(payload, expected)
            ):
                return payload
        except jwt.InvalidTokenError:
            pass
    return None


def _company_id_matches_resource(claims: dict, expected_resource: str) -> bool:
    expected_company = company_id_from_resource(expected_resource)
    if expected_company is None:
        return False
    try:
        return int(claims.get('company_id')) == int(expected_company)
    except (TypeError, ValueError):
        return False


def agent_scope_allows_ai(claims: dict) -> bool:
    scope = str(claims.get('scope') or '')
    parts = {part.strip() for part in scope.split() if part.strip()}
    return 'ai' in parts


def _truthy_claim(raw: object) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {'1', 'true', 'yes', 'on'}
    return False


def principal_from_agent_claims(claims: dict) -> StoragePrincipal:
    company_id = claims.get('company_id')
    try:
        cid = int(company_id)
    except (TypeError, ValueError) as exc:
        raise ValueError('Agent token is missing a numeric company_id.') from exc
    meta = claims.get('user_metadata')
    if not isinstance(meta, dict):
        meta = {}
    is_owner = _truthy_claim(
        claims.get('is_company_owner', meta.get('is_company_owner', False)),
    )
    return StoragePrincipal(
        user_id=0,
        company_id=cid,
        email='',
        username=f"agent:{claims.get('agent_id')}",
        is_staff=False,
        is_company_owner=is_owner,
        access_global_metrics=False,
        claims=claims,
    )


def _agent_staff_refused(claims: dict) -> bool:
    if claims.get('is_staff') or claims.get('is_superuser') or claims.get('is_global_staff'):
        return True
    user_meta = claims.get('user_metadata')
    if isinstance(user_meta, dict) and (
        user_meta.get('is_staff') or user_meta.get('is_superuser') or user_meta.get('is_global_staff')
    ):
        return True
    return False


def authenticate_agent_bearer(
    raw_token: str,
    *,
    expected_resource: str,
) -> tuple[StoragePrincipal, dict] | None:
    claims = _decode_agent_claims(raw_token, expected_resource=expected_resource)
    if claims is None:
        return None
    if _agent_staff_refused(claims):
        return None
    if not agent_scope_allows_ai(claims):
        return None
    if not personal_agent_bearer_valid(claims):
        return None
    principal = principal_from_agent_claims(claims)
    return principal, claims
