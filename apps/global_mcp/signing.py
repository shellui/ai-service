"""RS256 tokens. One signing key, a distinct aud per token kind."""

from __future__ import annotations

from datetime import datetime, timezone

import jwt
from django.conf import settings


def encode_rs256(claims: dict) -> str:
    key = getattr(settings, 'AI_SERVICE_SIGNING_KEY', None)
    if key is None:
        raise RuntimeError('AI_SERVICE_SIGNING_KEY is not configured.')
    return jwt.encode(claims, key.private_pem, algorithm='RS256', headers={'kid': key.kid})


def decode_rs256(token: str, *, audience: str, issuer: str | None = None) -> dict:
    key = getattr(settings, 'AI_SERVICE_SIGNING_KEY', None)
    if key is None:
        raise jwt.InvalidTokenError('signing key is not configured')
    return jwt.decode(
        token,
        key.public_pem,
        algorithms=['RS256'],
        audience=audience,
        issuer=(issuer if issuer is not None else settings.AI_SERVICE_ISSUER) or None,
        options={'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'jti']},
    )


def unix(moment: datetime) -> int:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())
