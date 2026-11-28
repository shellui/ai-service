"""Request short-lived downstream MCP access tokens from identity-service."""

from __future__ import annotations

import logging
import time

import jwt
import requests
from django.conf import settings
from shellui_django.mcp.delegation import (
    DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS,
    sign_downstream_token_request,
    verify_downstream_token_request,
)

from apps.connector.agent_record import AgentRecord

logger = logging.getLogger(__name__)

DOWNSTREAM_TOKEN_PATH = '/api/v1/mcp/internal/mcp-downstream-access-token'
_DEFAULT_REQUEST_TTL_SECONDS = 60
DELEGATED_GRANT_TTL_SECONDS = 60


def gateway_delegated_grant(action: str, *, now: int | None = None) -> dict[str, str | int]:
    """One-tool grant. Downstream skips a second approval only while ``exp`` is in the future."""
    name = str(action or '').strip()
    if not name:
        raise ValueError('delegated action is required')
    issued = int(time.time() if now is None else now)
    return {'action': name, 'exp': issued + DELEGATED_GRANT_TTL_SECONDS}


class DownstreamTokenError(Exception):
    pass


def _identity_origin() -> str:
    return (getattr(settings, 'IDENTITY_SERVICE_URL', '') or settings.IDENTITY_ISSUER or '').rstrip('/')


def mint_downstream_access_token(
    agent: AgentRecord,
    *,
    resource: str,
    delegated_action: str | None = None,
) -> str:
    """Ask identity to sign an agent access token for ``resource`` (downstream ``/mcp`` URL).

    ``delegated_action`` is the downstream tool name the gateway already allowed.
    The signed mint request carries ``mcp_gateway_delegated`` as ``{"action", "exp"}``.
    Identity copies that tool onto the access token it returns.
    """
    signing = getattr(settings, 'AI_SERVICE_SIGNING_KEY', None)
    issuer = (getattr(settings, 'AI_SERVICE_ISSUER', '') or '').strip().rstrip('/')
    if signing is None or not issuer:
        raise DownstreamTokenError('AI service delegation signing is not configured.')
    origin = _identity_origin()
    if not origin:
        raise DownstreamTokenError('IDENTITY_SERVICE_URL is not configured.')
    ttl = min(_DEFAULT_REQUEST_TTL_SECONDS, DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS)
    grant = None
    action = str(delegated_action or '').strip()
    if action:
        grant = gateway_delegated_grant(action)
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
        if grant is not None:
            claims = verify_downstream_token_request(assertion, signing.public_pem, issuer)
            claims['mcp_gateway_delegated'] = grant
            headers = {'kid': signing.kid} if signing.kid else None
            encoded = jwt.encode(claims, signing.private_pem, algorithm='RS256', headers=headers)
            assertion = encoded.decode('utf-8') if isinstance(encoded, bytes) else encoded
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
