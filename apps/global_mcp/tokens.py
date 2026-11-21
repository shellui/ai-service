"""Three token kinds, one key: MCP access, saas API, and the regional subject token."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.utils import timezone

from apps.connector.downstream_tokens import gateway_delegated_grant
from apps.global_mcp.models import GlobalAgent, GlobalAgentTokenAudit
from apps.global_mcp.resources import issuer, mcp_resource, saas_audience
from apps.global_mcp.signing import encode_rs256

TOKEN_MCP_ACCESS = 'mcp_access'
TOKEN_SAAS_API = 'saas_api'
TOKEN_AGENT_ACCESS = 'agent_access'
MCP_AUTHORITY_GLOBAL_DELEGATED = 'global_delegated'

REGIONAL_SERVICE_ORDER = ('ai', 'identity', 'storage', 'hosting', 'email')
SUBJECT_TTL_SECONDS = 120
SAAS_TTL_SECONDS = 300


def _base(agent: GlobalAgent, *, audience: str, token_type: str, ttl: timedelta) -> dict:
    now = timezone.now()
    exp = now + ttl
    return {
        'iss': issuer(),
        'aud': audience,
        'sub': agent.owner_sub,
        'agent_id': str(agent.id),
        'email': agent.owner_email,
        'email_verified': True,
        'token_type': token_type,
        'user_metadata': {'is_staff': False, 'is_superuser': False, 'is_global_staff': False},
        'jti': uuid.uuid4().hex,
        'iat': int(now.timestamp()),
        'exp': int(exp.timestamp()),
    }


def issue_mcp_access_token(agent: GlobalAgent) -> tuple[str, dict]:
    ttl = timedelta(seconds=int(settings.GLOBAL_MCP_ACCESS_TOKEN_TTL_SECONDS))
    claims = _base(agent, audience=mcp_resource(), token_type=TOKEN_MCP_ACCESS, ttl=ttl)
    claims['scope'] = 'mcp'
    if agent.name:
        claims['agent_name'] = agent.name
    token = encode_rs256(claims)
    _audit(agent, GlobalAgentTokenAudit.EVENT_ACCESS_MINT, claims)
    return token, claims


def issue_saas_api_token(
    agent: GlobalAgent,
    *,
    purpose: str = '',
    delegated_action: str = '',
) -> tuple[str, dict]:
    claims = _base(
        agent,
        audience=saas_audience(),
        token_type=TOKEN_SAAS_API,
        ttl=timedelta(seconds=SAAS_TTL_SECONDS),
    )
    claims['mcp_access'] = agent.access_mode
    claims['scope'] = 'saas'
    if purpose:
        claims['purpose'] = purpose
    action = str(delegated_action or '').strip()
    if action:
        claims['mcp_gateway_delegated'] = gateway_delegated_grant(action)
    token = encode_rs256(claims)
    _audit(agent, GlobalAgentTokenAudit.EVENT_SAAS, claims)
    return token, claims


def issue_subject_token(
    agent: GlobalAgent,
    *,
    global_company_id: str,
    binding_version: int,
    services: list[str],
    access_mode: str,
    read_level: str,
    destructive: bool,
    setup: dict | None = None,
) -> tuple[str, dict]:
    """Single-use subject token. Callers must not cache the token string."""
    allowed = [code for code in REGIONAL_SERVICE_ORDER if code in set(services)]
    claims = _base(
        agent,
        audience=str(settings.GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE),
        token_type=TOKEN_AGENT_ACCESS,
        ttl=timedelta(seconds=SUBJECT_TTL_SECONDS),
    )
    version = int(binding_version)
    claims.update(
        {
            'mcp_authority': MCP_AUTHORITY_GLOBAL_DELEGATED,
            'global_company_id': str(global_company_id),
            'company_binding_version': version,
            'grant_version': version,
            'scope': ' '.join(allowed),
            'mcp_access': access_mode,
            'mcp_read': read_level,
            'mcp_destructive': bool(destructive),
        }
    )
    if agent.name:
        claims['agent_name'] = agent.name
    if isinstance(setup, dict) and setup.get('active') is True:
        claims['setup_flow'] = True
        claims['mcp_new_company_grant'] = True
        claims['setup_context_company_id'] = int(setup['regional_company_id'])
        claims['setup_expires_at'] = int(setup['setup_expires_at'])
        claims['mcp_session_ttl_seconds'] = int(setup['mcp_session_ttl_seconds'])
    token = encode_rs256(claims)
    _audit(agent, GlobalAgentTokenAudit.EVENT_SUBJECT, claims, company_id=str(global_company_id))
    return token, claims


def _audit(agent: GlobalAgent, event: str, claims: dict, *, company_id: str = '') -> None:
    exp = datetime.fromtimestamp(int(claims['exp']), tz=dt_timezone.utc)
    GlobalAgentTokenAudit.objects.create(
        event_type=event,
        global_agent=agent,
        owner_sub=agent.owner_sub,
        global_company_id=company_id,
        jti=str(claims.get('jti') or ''),
        exp=exp,
        oauth_client_id=str(getattr(getattr(agent, 'oauth_client', None), 'client_id', '') or ''),
    )
