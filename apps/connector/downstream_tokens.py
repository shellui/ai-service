"""Request short-lived downstream MCP access tokens from identity-service."""

from __future__ import annotations

import logging

import requests
from django.conf import settings
from shellui_django.mcp.delegation import (
    DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS,
    sign_downstream_token_request,
)

from apps.connector.agent_record import AgentRecord

logger = logging.getLogger(__name__)

DOWNSTREAM_TOKEN_PATH = '/api/v1/mcp/internal/mcp-downstream-access-token'
_DEFAULT_REQUEST_TTL_SECONDS = 60


class DownstreamTokenError(Exception):
    pass


def _identity_origin() -> str:
    return (getattr(settings, 'IDENTITY_SERVICE_URL', '') or settings.IDENTITY_ISSUER or '').rstrip('/')


def mint_downstream_access_token(agent: AgentRecord, *, resource: str) -> str:
    """Ask identity to sign an agent access token for ``resource`` (downstream ``/mcp`` URL)."""
    signing = getattr(settings, 'AI_SERVICE_SIGNING_KEY', None)
    issuer = (getattr(settings, 'AI_SERVICE_ISSUER', '') or '').strip().rstrip('/')
    if signing is None or not issuer:
        raise DownstreamTokenError('AI service delegation signing is not configured.')
    origin = _identity_origin()
    if not origin:
        raise DownstreamTokenError('IDENTITY_SERVICE_URL is not configured.')
    ttl = min(_DEFAULT_REQUEST_TTL_SECONDS, DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS)
    try:
        assertion = sign_downstream_token_request(
            signing.private_pem,
            signing.kid,
            issuer,
            agent.agent_id,
            agent.company_id,
            resource,
            ttl,
        )
    except Exception as exc:
        logger.warning('Downstream token request signing failed err=%s', type(exc).__name__)
        raise DownstreamTokenError('Could not sign downstream token request.') from exc
    url = f'{origin}{DOWNSTREAM_TOKEN_PATH}'
    timeout = float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 5))
    try:
        response = requests.post(
            url,
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
