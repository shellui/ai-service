"""RFC 8693 subject-token exchange at the company's region identity. The subject token is never cached."""

from __future__ import annotations

import time
from typing import Any

import requests
from django.core.cache import cache

from apps.global_mcp.models import GlobalAgent
from apps.global_mcp.tokens import issue_subject_token

GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange'
ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
_CACHE_SKEW_SECONDS = 30


class ExchangeError(Exception):
    def __init__(self, code: str, description: str) -> None:
        super().__init__(description or code)
        self.code = code
        self.description = description


def _cache_key(agent_id: str, company_id: str, services: list[str], binding_version: int) -> str:
    # A new binding version (narrow or revoke) never reuses a cached regional token.
    return 'global_mcp:regional:' + ':'.join([agent_id, company_id, '-'.join(services), str(binding_version)])


def regional_access_token(
    agent: GlobalAgent,
    company: dict,
    *,
    identity_url: str,
    resource: str,
    services: list[str],
    binding_version: int,
    access_mode: str,
    read_level: str,
    destructive: bool,
    setup: dict | None = None,
) -> str:
    company_id = str(company.get('id') or '')
    key = _cache_key(str(agent.id), company_id, services, binding_version)
    cached = cache.get(key)
    now = int(time.time())
    if isinstance(cached, dict) and int(cached.get('exp') or 0) - _CACHE_SKEW_SECONDS > now:
        token = str(cached.get('access_token') or '')
        if token:
            return token
    subject, _claims = issue_subject_token(
        agent,
        global_company_id=company_id,
        binding_version=binding_version,
        services=services,
        access_mode=access_mode,
        read_level=read_level,
        destructive=destructive,
        setup=setup,
    )
    # The subject token is used once, on this request, and is not stored.
    regional_id = str(company.get('regional_company_id') or '').strip()
    response = requests.post(
        f"{identity_url.rstrip('/')}/oauth/mcp/token",
        json={
            'grant_type': GRANT_TYPE,
            'subject_token': subject,
            'subject_token_type': ACCESS_TOKEN_TYPE,
            'requested_token_type': ACCESS_TOKEN_TYPE,
            'company_id': int(regional_id),
            'resource': resource,
            'services': services,
        },
        timeout=10,
    )
    try:
        payload: Any = response.json()
    except ValueError as exc:
        raise ExchangeError('invalid_grant', 'Region identity did not return JSON.') from exc
    if response.status_code >= 400 or not isinstance(payload, dict) or not payload.get('access_token'):
        description = ''
        if isinstance(payload, dict):
            description = str(payload.get('error_description') or payload.get('error') or '')
        raise ExchangeError('invalid_grant', description or 'Region identity refused the exchange.')
    expires_in = int(payload.get('expires_in') or 60)
    cache.set(
        key,
        {'access_token': payload['access_token'], 'exp': now + max(expires_in, 1)},
        timeout=max(expires_in, 1),
    )
    return str(payload['access_token'])
