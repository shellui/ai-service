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


def elicitation_declined_text(*, tool_name: str) -> str:
    return f'You declined the approval link for {tool_name}. Nothing was changed.'


def pending_agent_instruction(*, tool_name: str) -> str:
    return (
        f'Show this link to the user and ask them to approve {tool_name}. '
        'After they approve, call this tool again with the same arguments. '
        'You can also call ai_get_approval with the approval_id to check the decision.'
    )


def url_elicitation_message(*, tool_name: str) -> str:
    return f'Approve {tool_name} in your browser, then return here.'


def form_approval_message(*, tool_name: str) -> str:
    return f'Allow {tool_name}? Choose Approve or Deny.'


def form_approval_instruction(*, tool_name: str) -> str:
    return (
        f'Ask the user to approve or deny {tool_name} in chat. '
        'After they approve, call this tool again with the same arguments and their decision.'
    )


def form_consent_failed_text() -> str:
    return 'Approval could not be recorded. Try again shortly.'


def approved_retry_instruction(*, tool_name: str) -> str:
    return f'Approved. Call {tool_name} again with the same arguments. It will run once.'


def approval_create_failed_text(reason: str) -> str:
    """User-facing text when Identity cannot create an approval. No secrets, tokens, or response bodies."""
    code = str(reason or '').strip()
    if code == 'identity_unreachable':
        return 'Approval could not be requested because Shellui identity is unreachable. Try again shortly.'
    if code == 'signing_not_configured':
        return 'Approval could not be requested because signing is not configured.'
    if code == 'blocked_assertion':
        return 'Approval could not be requested because this agent cannot request approvals.'
    if code == 'identity_not_configured':
        return 'Approval could not be requested because Shellui identity is not configured.'
    if code == 'identity_rejected':
        return 'Approval could not be requested. Shellui identity rejected the request.'
    if code == 'invalid_response':
        return 'Approval could not be requested because Shellui identity returned an unexpected response.'
    return 'Approval could not be requested. Try again shortly.'


def fallback_pending_text(*, settings_url: str) -> str:
    return f'Approval required. Open Shellui Settings (MCP approvals) to allow or deny: {settings_url}'
