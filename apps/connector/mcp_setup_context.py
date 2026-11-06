"""Server-derived MCP approval assertion context (setup session vs default).

Identity verifies signed assertions only; values like ``setup_flow`` and
``mcp_session_ttl_seconds`` must come from the regional access token (identity-
issued), never from tool arguments.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from django.conf import settings

logger = logging.getLogger(__name__)

# Default shellui-django internal assertion window for ordinary approvals.
_DEFAULT_APPROVAL_ASSERTION_LIFETIME = 60


def _truthy_setup_flow(raw: object) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {'1', 'true', 'yes', 'on', 'setup', 'setup_flow', 'new_company'}
    return False


def session_allow_ttl_bounds() -> tuple[int, int]:
    """Bounds for ``mcp_session_ttl_seconds`` during setup (must match identity-service)."""
    lo = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS', 600) or 600)
    hi = int(getattr(settings, 'MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS', 900) or 900)
    if lo > hi:
        lo, hi = hi, lo
    return lo, hi


def _max_assertion_lifetime_seconds() -> int:
    return max(
        _DEFAULT_APPROVAL_ASSERTION_LIFETIME,
        int(getattr(settings, 'MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS', 900) or 900),
    )


def _seconds_until_access_token_exp(agent_claims: dict) -> int | None:
    """Wall-clock seconds until ``exp`` (not ``exp - iat``), for capping setup authority."""
    try:
        exp = int(agent_claims['exp'])
    except (KeyError, TypeError, ValueError):
        return None
    return max(0, exp - int(time.time()))


@dataclass(frozen=True, slots=True)
class ApprovalAssertionContext:
    """Lifetime and optional setup claims copied into signed approval assertions."""

    lifetime_seconds: int
    setup_flow: bool = False
    mcp_session_ttl_seconds: int | None = None


def _fallback_context() -> ApprovalAssertionContext:
    return ApprovalAssertionContext(lifetime_seconds=_DEFAULT_APPROVAL_ASSERTION_LIFETIME)


def approval_assertion_context_from_agent_claims(agent_claims: dict | None) -> ApprovalAssertionContext:
    """
    Build assertion TTL and optional setup fields from verified agent JWT claims.

    Falls back to a 60s assertion when setup is absent, invalid, or exceeds the
    JWT validity window (``exp`` - ``iat``).
    """
    if not isinstance(agent_claims, dict):
        return _fallback_context()

    if not _truthy_setup_flow(agent_claims.get('setup_flow')):
        return _fallback_context()

    raw_ttl = agent_claims.get('mcp_session_ttl_seconds')
    try:
        setup_ttl = int(raw_ttl)
    except (TypeError, ValueError):
        return _fallback_context()

    lo, hi = session_allow_ttl_bounds()
    if setup_ttl < lo or setup_ttl > hi:
        return _fallback_context()

    max_from_jwt: int | None = None
    try:
        exp = int(agent_claims['exp'])
        iat = int(agent_claims['iat'])
        if exp > iat:
            max_from_jwt = exp - iat
    except (KeyError, TypeError, ValueError):
        max_from_jwt = None

    wall_remaining = _seconds_until_access_token_exp(agent_claims)

    cap = _max_assertion_lifetime_seconds()
    if max_from_jwt is not None:
        cap = min(cap, max_from_jwt)
    if wall_remaining is not None:
        cap = min(cap, wall_remaining)

    if setup_ttl > cap:
        logger.info(
            'MCP setup assertion TTL ignored (exceeds cap): company_id=%s agent_id=%s setup_ttl=%s cap=%s',
            agent_claims.get('company_id'),
            agent_claims.get('agent_id'),
            setup_ttl,
            cap,
        )
        return _fallback_context()

    # JWT lifetime must cover the session TTL identity will grant (<= exp - iat).
    lifetime = max(_DEFAULT_APPROVAL_ASSERTION_LIFETIME, setup_ttl)
    lifetime = min(lifetime, cap)
    if wall_remaining is not None and lifetime > wall_remaining:
        logger.info(
            'MCP setup assertion TTL ignored (exceeds access token wall time): company_id=%s agent_id=%s lifetime=%s wall=%s',
            agent_claims.get('company_id'),
            agent_claims.get('agent_id'),
            lifetime,
            wall_remaining,
        )
        return _fallback_context()
    if lifetime < setup_ttl:
        return _fallback_context()

    return ApprovalAssertionContext(
        lifetime_seconds=lifetime,
        setup_flow=True,
        mcp_session_ttl_seconds=setup_ttl,
    )
