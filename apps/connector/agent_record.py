"""Agent view derived from validated JWT claims (no local Agent database)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shellui_django.mcp.gateway import scope_service_ids


def _persisted_services_claim(claims: dict[str, Any]) -> list[str] | None:
    """Identity-persisted MCP service allow list, if present on the token (OAuth scope may be wider)."""
    raw = claims.get('services_allowed')
    if raw is None:
        raw = claims.get('services')
    if raw is None:
        return None
    if not isinstance(raw, list):
        return None
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    if not out:
        return []
    return sorted(set(out))


def _effective_services_allowed(claims: dict[str, Any]) -> list[str]:
    """
    Services the agent may use for downstream MCP and gateway catalog filtering.

    ``scope`` is the OAuth-style superset on the JWT; Identity may also emit a narrower
    ``services_allowed`` (or legacy ``services``) row snapshot. When that list is present,
    intersect — never treat a broad OAuth scope as proof of a downstream grant that was
    not persisted for the agent.
    """
    scope_ids = {s for s in scope_service_ids(claims) if isinstance(s, str) and s.strip()}
    persisted = _persisted_services_claim(claims)
    if persisted is None:
        return sorted(scope_ids)
    effective = scope_ids & set(persisted)
    return sorted(effective)


@dataclass(frozen=True, slots=True)
class AgentRecord:
    agent_id: str
    company_id: int
    services_allowed: list[str]

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> AgentRecord | None:
        agent_id = str(claims.get('agent_id') or '').strip()
        company_id = claims.get('company_id')
        if not agent_id or company_id is None:
            return None
        try:
            cid = int(company_id)
        except (TypeError, ValueError):
            return None
        services = _effective_services_allowed(claims)
        return cls(agent_id=agent_id, company_id=cid, services_allowed=services)
