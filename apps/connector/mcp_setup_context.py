"""Server-derived MCP approval assertion context (setup session vs default).

Identity verifies signed assertions only; values like ``setup_flow`` and
``mcp_session_ttl_seconds`` must come from the regional access token (identity-
issued), never from tool arguments.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.connector.mcp_company_id import strict_numeric_company_id

logger = logging.getLogger(__name__)

# Default shellui-django internal assertion window for ordinary approvals.
_DEFAULT_APPROVAL_ASSERTION_LIFETIME = 60


def _bool_claim(raw: object) -> bool:
    """Strict JWT boolean: only true or case-insensitive 'true' (identity-issued)."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() == 'true'
    return False


def parse_int_version_claim(raw: object) -> int | None:
    """Strict nonnegative int from JWT only (commons #14: ``None`` vs ``0``; no string claims)."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    return None


def parse_setup_expires_at_claim(raw: object, *, wall_max_exp: int) -> timezone.datetime | None:
    """Identity-issued ``setup_expires_at``: ISO-8601 string or Unix epoch **int** seconds (not bool)."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    dt: timezone.datetime | None = None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        try:
            ts = float(raw)
        except (TypeError, ValueError):
            return None
        if ts <= 0:
            return None
        dt = datetime.fromtimestamp(ts, tz=dt_timezone.utc)
    else:
        text = str(raw).strip()
        if not text:
            return None
        dt = parse_datetime(text)
    if dt is None:
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, dt_timezone.utc)
    now = timezone.now()
    if dt <= now:
        return None
    wall_max = datetime.fromtimestamp(float(wall_max_exp), tz=dt_timezone.utc)
    if dt > wall_max:
        return None
    return dt


def parse_global_company_id(raw: object) -> str | None:
    """Delegated global company id: canonical UUID string (commons #14 ``_normalize_uuid_string`` alignment).

    Accepts only ``str`` or ``uuid.UUID`` (after strip for strings). Rejects arbitrary objects
    coerced via ``str()`` so only real UUID text or a ``UUID`` instance normalizes to
    ``str(parsed)`` (whitespace around UUID text is stripped; output is canonical hex with hyphens).
    """
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, uuid.UUID):
        return str(raw)
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    try:
        return str(uuid.UUID(s))
    except ValueError:
        return None


def global_binding_triplet_from_claims(agent_claims: dict | None) -> tuple[int | None, int | None, str | None]:
    """Parse grant_version, company_binding_version, global_company_id (each strict or None)."""
    if not isinstance(agent_claims, dict):
        return None, None, None
    return (
        parse_int_version_claim(agent_claims.get('grant_version')),
        parse_int_version_claim(agent_claims.get('company_binding_version')),
        parse_global_company_id(agent_claims.get('global_company_id')),
    )


def is_global_delegated_claims(agent_claims: dict | None) -> bool:
    """
    Global (company-scoped) regional agent: **authoritative** complete triple from identity #135.

    Identity may still issue ``personal_token_id`` on delegated tokens; do **not** infer mode from
    that claim. Delegation is detected only by canonical ``global_company_id`` plus both nonnegative
    int versions (``0`` is valid).
    """
    gv, cbv, gcid = global_binding_triplet_from_claims(agent_claims)
    return gv is not None and cbv is not None and gcid is not None


def global_binding_conflict_claims(agent_claims: dict | None) -> bool:
    """
    True if some but not all of the global triple are present or parseable (reject; no legacy guess).
    """
    if not isinstance(agent_claims, dict):
        return False
    raw_gcid = agent_claims.get('global_company_id')
    gv, cbv, gcid = global_binding_triplet_from_claims(agent_claims)
    has_raw_gcid = not (
        raw_gcid is None or (isinstance(raw_gcid, str) and raw_gcid.strip() == '')
    )
    if gv is not None and cbv is not None and gcid is not None:
        return False
    if gv is None and cbv is None and gcid is None and not has_raw_gcid:
        return False
    if has_raw_gcid and gcid is None:
        return True
    return True


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
    setup_expires_at: timezone.datetime | None = None
    grant_version: int | None = None
    company_binding_version: int | None = None
    global_company_id: str | None = None
    is_global_delegated: bool = False
    blocked_assertion: bool = False


def _fallback_context(
    agent_claims: dict | None = None,
    *,
    setup_claim_rejected: bool = False,
) -> ApprovalAssertionContext:
    gv: int | None = None
    cbv: int | None = None
    gcid: str | None = None
    if isinstance(agent_claims, dict):
        gv, cbv, gcid = global_binding_triplet_from_claims(agent_claims)
    is_gd = is_global_delegated_claims(agent_claims)
    conflict = global_binding_conflict_claims(agent_claims)
    blocked = bool(setup_claim_rejected or conflict)
    return ApprovalAssertionContext(
        lifetime_seconds=_DEFAULT_APPROVAL_ASSERTION_LIFETIME,
        grant_version=gv,
        company_binding_version=cbv,
        global_company_id=gcid,
        is_global_delegated=is_gd,
        blocked_assertion=blocked,
    )


def approval_assertion_context_from_agent_claims(agent_claims: dict | None) -> ApprovalAssertionContext:
    """
    Build assertion TTL and optional setup fields from verified agent JWT claims.

    Falls back to a 60s assertion when setup is absent, invalid, or exceeds the
    JWT validity window (``exp`` - ``iat``).
    """
    if not isinstance(agent_claims, dict):
        return _fallback_context()

    is_gd = is_global_delegated_claims(agent_claims)
    if global_binding_conflict_claims(agent_claims):
        return _fallback_context(agent_claims)

    if agent_claims.get('setup_flow') is not True:
        return _fallback_context(agent_claims)

    # Long setup session is only for the new-company delegation grant (identity #135 snapshot).
    if agent_claims.get('mcp_new_company_grant') is not True:
        logger.info(
            'MCP setup assertion rejected (not a new-company grant): agent_id=%s',
            agent_claims.get('agent_id'),
        )
        return _fallback_context(agent_claims, setup_claim_rejected=True)

    if strict_numeric_company_id(agent_claims.get('company_id')) is None:
        logger.info(
            'MCP setup assertion rejected (invalid company_id in agent claims): agent_id=%s company_id=%r',
            agent_claims.get('agent_id'),
            agent_claims.get('company_id'),
        )
        return _fallback_context(agent_claims, setup_claim_rejected=True)

    gv = parse_int_version_claim(agent_claims.get('grant_version'))
    cbv = parse_int_version_claim(agent_claims.get('company_binding_version'))
    gcid = parse_global_company_id(agent_claims.get('global_company_id'))
    if gv is None or cbv is None or gcid is None:
        logger.info(
            'MCP setup assertion rejected (missing grant_version, company_binding_version, or global_company_id): agent_id=%s',
            agent_claims.get('agent_id'),
        )
        return _fallback_context(agent_claims, setup_claim_rejected=True)

    raw_ttl = agent_claims.get('mcp_session_ttl_seconds')
    try:
        setup_ttl = int(raw_ttl)
    except (TypeError, ValueError):
        return _fallback_context(agent_claims, setup_claim_rejected=True)

    lo, hi = session_allow_ttl_bounds()
    if setup_ttl < lo or setup_ttl > hi:
        return _fallback_context(agent_claims, setup_claim_rejected=True)

    max_from_jwt: int | None = None
    try:
        exp = int(agent_claims['exp'])
        iat = int(agent_claims['iat'])
        if exp > iat:
            max_from_jwt = exp - iat
    except (KeyError, TypeError, ValueError):
        max_from_jwt = None

    wall_remaining = _seconds_until_access_token_exp(agent_claims)
    # Setup window 600–900s only when more than 600s remain on the access token; otherwise ordinary 60s cap.
    lo, _hi = session_allow_ttl_bounds()
    if wall_remaining is not None and wall_remaining <= lo:
        logger.info(
            'MCP setup assertion rejected (access token wall <= %ss): company_id=%s agent_id=%s wall=%s',
            lo,
            agent_claims.get('company_id'),
            agent_claims.get('agent_id'),
            wall_remaining,
        )
        return _fallback_context(agent_claims, setup_claim_rejected=True)

    try:
        wall_max_exp = int(agent_claims['exp'])
    except (KeyError, TypeError, ValueError):
        wall_max_exp = int(time.time())
    raw_setup_exp = agent_claims.get('setup_expires_at')
    if raw_setup_exp is None or (isinstance(raw_setup_exp, str) and not str(raw_setup_exp).strip()):
        logger.info(
            'MCP setup assertion rejected (missing setup_expires_at): company_id=%s agent_id=%s',
            agent_claims.get('company_id'),
            agent_claims.get('agent_id'),
        )
        return _fallback_context(agent_claims, setup_claim_rejected=True)
    setup_expires_at = parse_setup_expires_at_claim(raw_setup_exp, wall_max_exp=wall_max_exp)
    if setup_expires_at is None:
        logger.info(
            'MCP setup assertion rejected (invalid setup_expires_at): company_id=%s agent_id=%s',
            agent_claims.get('company_id'),
            agent_claims.get('agent_id'),
        )
        return _fallback_context(agent_claims, setup_claim_rejected=True)

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
        return _fallback_context(agent_claims, setup_claim_rejected=True)

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
        return _fallback_context(agent_claims, setup_claim_rejected=True)
    if lifetime < setup_ttl:
        return _fallback_context(agent_claims, setup_claim_rejected=True)

    if setup_expires_at is not None:
        cap_seconds = (setup_expires_at - timezone.now()).total_seconds()
        if cap_seconds < setup_ttl:
            logger.info(
                'MCP setup assertion rejected (setup_expires_at before ttl window): company_id=%s agent_id=%s',
                agent_claims.get('company_id'),
                agent_claims.get('agent_id'),
            )
            return _fallback_context(agent_claims, setup_claim_rejected=True)

    return ApprovalAssertionContext(
        lifetime_seconds=lifetime,
        setup_flow=True,
        mcp_session_ttl_seconds=setup_ttl,
        setup_expires_at=setup_expires_at,
        grant_version=gv,
        company_binding_version=cbv,
        global_company_id=gcid,
        is_global_delegated=is_gd,
        blocked_assertion=False,
    )
