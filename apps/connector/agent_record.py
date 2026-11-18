"""Agent view derived from validated JWT claims (no local Agent database)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shellui_django.mcp.gateway import scope_service_ids


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
        scope = sorted(scope_service_ids(claims))
        return cls(agent_id=agent_id, company_id=cid, services_allowed=scope)
