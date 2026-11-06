"""Trusted revocation snapshot helpers (commons #14 authority rows)."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from django.core.cache import cache

from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_setup_context import parse_global_company_id, parse_int_version_claim

logger = logging.getLogger(__name__)

_REVOKED_CACHE_KEY = 'mcp:revoked_trusted_payload'


def _cached_payload() -> dict[str, Any] | None:
    raw = cache.get(_REVOKED_CACHE_KEY)
    return raw if isinstance(raw, dict) else None


def cached_revocation_snapshot() -> dict[str, Any] | None:
    """Trusted revocation body shape stored by :mod:`apps.connector.mcp_identity`."""
    return _cached_payload()


def delegation_authority_consistent_with_revocation(
    *,
    agent_id: str,
    company_id: int,
    agent_claims: dict[str, Any],
) -> bool:
    """
    For **delegated** regional JWTs (no ``personal_token_id``), ensure global triple matches the
    trusted Identity revocation ``agents[]`` row when present (fail closed on mismatch or
    ``mcp_authority_snapshot_rejected``).
    """
    if str(agent_claims.get('personal_token_id') or '').strip():
        return True
    jwt_gv = parse_int_version_claim(agent_claims.get('grant_version'))
    jwt_gcid = parse_global_company_id(agent_claims.get('global_company_id'))
    jwt_cbv = parse_int_version_claim(agent_claims.get('company_binding_version'))
    if jwt_gv is None or jwt_gcid is None or jwt_cbv is None:
        return False
    payload = _cached_payload()
    if payload is None:
        # No trusted snapshot yet (cache cold); higher layers already fail closed on revocation poll outage.
        return True
    agents = payload.get('agents') or []
    if not isinstance(agents, list):
        return False
    for row in agents:
        if not isinstance(row, dict):
            continue
        if str(row.get('agent_id') or '') != str(agent_id):
            continue
        rcid = strict_numeric_company_id(row.get('company_id'))
        if rcid is None or rcid != int(company_id):
            continue
        if row.get('mcp_authority_snapshot_rejected') is True:
            logger.info(
                'MCP delegation authority rejected by revocation snapshot: agent_id=%s company_id=%s',
                agent_id,
                company_id,
            )
            return False
        row_gcid = row.get('global_company_id')
        if row_gcid is None:
            return True
        try:
            row_uuid = str(uuid.UUID(str(row_gcid).strip()))
        except ValueError:
            return False
        if row_uuid != jwt_gcid:
            return False
        row_gv = parse_int_version_claim(row.get('grant_version'))
        if row_gv is None or row_gv != jwt_gv:
            return False
        return True
    # No matching row for this agent/company: nothing in the trusted snapshot contradicts the JWT.
    return True


def revocation_fingerprint_material(payload: dict[str, Any]) -> str:
    """Stable JSON for hashing (sorted keys, no whitespace)."""
    ids = sorted(str(x) for x in (payload.get('revoked_ids') or []))
    agents = payload.get('agents') or []
    policy = payload.get('revocation_policy_version')
    max_gv = payload.get('max_active_grant_version')
    return json.dumps(
        {
            'agent_ids': ids,
            'agents': agents,
            'revocation_policy_version': policy,
            'max_active_grant_version': max_gv,
        },
        sort_keys=True,
        separators=(',', ':'),
        default=str,
    )
