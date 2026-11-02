"""Request short-lived downstream MCP access tokens from identity-service."""

from __future__ import annotations

import logging
import time
import uuid

import jwt
import requests
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings

from apps.connector.agent_record import AgentRecord

logger = logging.getLogger(__name__)

# Proposed identity internal API; constants belong in shellui_django.mcp.internal (not yet shipped).
DOWNSTREAM_TOKEN_AUDIENCE = 'shellui-mcp-downstream-token'
DOWNSTREAM_TOKEN_SCOPE = 'mcp.downstream_token.mint'
DOWNSTREAM_TOKEN_PATH = '/api/v1/mcp/internal/mcp-downstream-access-token'


class DownstreamTokenError(Exception):
    pass


def _identity_origin() -> str:
    return (getattr(settings, 'IDENTITY_SERVICE_URL', '') or settings.IDENTITY_ISSUER or '').rstrip('/')


def build_downstream_token_assertion(*, audience_url: str, lifetime_seconds: int = 60) -> str:
    now = int(time.time())
    claims = {
        'iss': api_settings.ISSUER or '',
        'aud': DOWNSTREAM_TOKEN_AUDIENCE,
        'sub': 'service',
        'scope': DOWNSTREAM_TOKEN_SCOPE,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    headers = {}
    kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
    if kid:
        headers['kid'] = kid
    token = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm=api_settings.ALGORITHM, headers=headers or None)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def mint_downstream_access_token(agent: AgentRecord, *, resource: str) -> str:
    """Ask identity to sign an agent access token for ``resource`` (downstream ``/mcp`` URL)."""
    origin = _identity_origin()
    if not origin:
        raise DownstreamTokenError('IDENTITY_SERVICE_URL is not configured.')
    url = f'{origin}{DOWNSTREAM_TOKEN_PATH}'
    assertion = build_downstream_token_assertion(audience_url=origin)
    body = {
        'agent_id': agent.agent_id,
        'company_id': agent.company_id,
        'resource': resource,
    }
    timeout = float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 5))
    try:
        response = requests.post(
            url,
            json=body,
            headers={'Authorization': f'Bearer {assertion}', 'Content-Type': 'application/json'},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.warning('Downstream token mint transport error err=%s', type(exc).__name__)
        raise DownstreamTokenError('Identity unreachable.') from exc
    if response.status_code == 404:
        raise DownstreamTokenError(
            'Identity downstream token endpoint is not available yet (expected POST '
            f'{DOWNSTREAM_TOKEN_PATH}).'
        )
    if response.status_code >= 400:
        logger.warning('Downstream token mint HTTP %s', response.status_code)
        raise DownstreamTokenError('Identity rejected downstream token request.')
    try:
        payload = response.json()
    except ValueError as exc:
        raise DownstreamTokenError('Invalid identity response.') from exc
    token = payload.get('access_token') or payload.get('token')
    if not token or not str(token).strip():
        raise DownstreamTokenError('Identity response missing access_token.')
    return str(token).strip()
