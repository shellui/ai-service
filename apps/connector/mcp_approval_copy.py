"""Shellui MCP approval elicitation copy (Wilson v1, 2026-11-05)."""

from __future__ import annotations

SESSION_SECONDS = 60


def approval_title(*, tool_name: str, destructive: bool) -> str:
    if destructive:
        return f'Allow {tool_name}? This can change data.'
    return f'Allow {tool_name}?'


def approval_body(*, agent_name: str, tool_name: str, company_name: str) -> str:
    return f'{agent_name} wants to run {tool_name} on {company_name}.'


def approval_batch_body(*, agent_name: str, tool_name: str, company_name: str, tool_count: int) -> str:
    return (
        f'{agent_name} wants to run {tool_count} tools on {company_name}, including {tool_name}.'
    )


def session_helper_text(*, seconds: int | None = None) -> str:
    sec = int(seconds) if seconds is not None else SESSION_SECONDS
    return (
        f'For {sec} seconds on this connection. '
        'Tools that change data still ask again.'
    )


def after_deny_text(*, tool_name: str) -> str:
    return f'You denied {tool_name}.'


def after_session_allow_text(*, seconds: int | None = None) -> str:
    sec = int(seconds) if seconds is not None else SESSION_SECONDS
    return f'Allowed for {sec} seconds on this connection.'


def expired_text() -> str:
    return 'This approval expired. Ask the agent to try again.'


def fallback_pending_text(*, settings_url: str) -> str:
    return f'Approval required. Open Shellui Settings (MCP approvals) to allow or deny: {settings_url}'
