"""Approvals for global saas tools. Destructive actions always use a link. Project deletion is refused."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.connector.mcp_discovery import redact_arguments
from apps.global_mcp.copy import DESTROY_REFUSED
from apps.global_mcp.models import (
    GlobalAgent,
    GlobalMcpApprovalDecisionAudit,
    GlobalMcpApprovalRequest,
    GlobalMcpApprovalSessionGrant,
)

DESTROY_TOOL = 'saas_delete_companies'


@dataclass
class ApprovalDecision:
    allowed: bool
    channel: str = 'none'
    approval: GlobalMcpApprovalRequest | None = None
    error: str = ''


def arguments_hash(arguments: dict) -> str:
    payload = json.dumps(arguments or {}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def approval_url(approval_id) -> str:
    base = str(getattr(settings, 'AI_PUBLIC_URL', '') or getattr(settings, 'AI_SERVICE_ISSUER', '') or '').rstrip('/')
    return f'{base}/oauth/mcp/approvals/{approval_id}'


def _session_ttl(agent: GlobalAgent) -> int:
    if agent.setup_flow and agent.setup_expires_at and timezone.now() < agent.setup_expires_at:
        return int(settings.MCP_SETUP_APPROVAL_SESSION_TTL_SECONDS)
    return int(settings.MCP_APPROVAL_SESSION_TTL_SECONDS)


def session_allows(agent: GlobalAgent, tool: dict, arguments: dict, connection_id: str) -> bool:
    meta = tool.get('_meta') or {}
    if meta.get('destructive'):
        return False
    now = timezone.now()
    return GlobalMcpApprovalSessionGrant.objects.filter(
        agent_id=agent.id,
        action=str(tool.get('name') or ''),
        arguments_hash=arguments_hash(arguments),
        connection_id=connection_id or str(agent.id),
        expires_at__gt=now,
        revoked_at__isnull=True,
    ).exists()


def decide(agent: GlobalAgent, tool: dict, arguments: dict, *, connection_id: str = '') -> ApprovalDecision:
    name = str(tool.get('name') or '')
    meta = tool.get('_meta') or {}
    read_only = bool(meta.get('read_only'))
    destructive = bool(meta.get('destructive')) or name == DESTROY_TOOL
    if name == DESTROY_TOOL:
        return ApprovalDecision(allowed=False, error=DESTROY_REFUSED)
    if read_only and not destructive:
        if meta.get('sensitive') and agent.read_level != GlobalAgent.READ_SENSITIVE:
            return ApprovalDecision(allowed=False, error='This read needs the sensitive read level.')
        return ApprovalDecision(allowed=True)
    if agent.access_mode == GlobalAgent.ACCESS_READ_ONLY:
        return ApprovalDecision(allowed=False, error='This agent is read only.')
    if session_allows(agent, tool, arguments, connection_id):
        return ApprovalDecision(allowed=True, channel='session')
    if destructive and not agent.allow_destructive_without_asking:
        return ApprovalDecision(allowed=False, error='Destructive actions are not allowed for this agent.')
    channel = 'link' if destructive else 'form'
    if agent.access_mode == GlobalAgent.ACCESS_FULL and not destructive:
        return ApprovalDecision(allowed=True)
    pending = _open_approval(agent, tool, arguments, channel=channel, destructive=destructive)
    return ApprovalDecision(allowed=False, channel=channel, approval=pending)


def _open_approval(agent, tool, arguments, *, channel: str, destructive: bool) -> GlobalMcpApprovalRequest:
    digest = arguments_hash(arguments)
    name = str(tool.get('name') or '')
    existing = (
        GlobalMcpApprovalRequest.objects.filter(
            agent=agent,
            action=name,
            arguments_hash=digest,
            status=GlobalMcpApprovalRequest.STATUS_APPROVED,
            executed_at__isnull=True,
            expires_at__gt=timezone.now(),
        )
        .order_by('-created_at')
        .first()
    )
    if existing is not None:
        return existing
    meta = tool.get('_meta') or {}
    ttl = _session_ttl(agent) if channel == 'form' else 600
    row = GlobalMcpApprovalRequest.objects.create(
        agent=agent,
        owner_sub=agent.owner_sub,
        kind=GlobalMcpApprovalRequest.KIND_TOOL,
        service='saas',
        action=name,
        arguments_hash=digest,
        arguments_redacted=redact_arguments(arguments) if isinstance(arguments, dict) else {},
        arguments=arguments if isinstance(arguments, dict) else {},
        is_destructive=destructive,
        channel=channel,
        short_action_summary=str(tool.get('description') or name)[:500],
        method=str(meta.get('method') or ''),
        path=str(meta.get('path') or ''),
        status=GlobalMcpApprovalRequest.STATUS_PENDING,
        expires_at=timezone.now() + timedelta(seconds=max(ttl, 60)),
    )
    return row


def consume_approved(agent: GlobalAgent, tool: dict, arguments: dict) -> GlobalMcpApprovalRequest | None:
    row = (
        GlobalMcpApprovalRequest.objects.filter(
            agent=agent,
            action=str(tool.get('name') or ''),
            arguments_hash=arguments_hash(arguments),
            status=GlobalMcpApprovalRequest.STATUS_APPROVED,
            executed_at__isnull=True,
            expires_at__gt=timezone.now(),
        )
        .order_by('-created_at')
        .first()
    )
    return row


def mark_executed(row: GlobalMcpApprovalRequest, *, connection_id: str = '') -> None:
    now = timezone.now()
    row.status = GlobalMcpApprovalRequest.STATUS_EXECUTED
    row.executed_at = now
    row.save(update_fields=['status', 'executed_at'])
    if row.channel == 'form' and not row.is_destructive:
        GlobalMcpApprovalSessionGrant.objects.create(
            agent_id=row.agent_id,
            service=row.service,
            action=row.action,
            arguments_hash=row.arguments_hash,
            connection_id=connection_id or str(row.agent_id),
            expires_at=now + timedelta(seconds=_session_ttl(row.agent)),
        )


def decide_page(approval: GlobalMcpApprovalRequest, *, actor_sub: str, allow: bool) -> str:
    if approval.owner_sub != actor_sub:
        return 'forbidden'
    if approval.status != GlobalMcpApprovalRequest.STATUS_PENDING:
        return approval.status
    if approval.expires_at <= timezone.now():
        approval.status = GlobalMcpApprovalRequest.STATUS_EXPIRED
        approval.save(update_fields=['status'])
        return 'expired'
    approval.status = GlobalMcpApprovalRequest.STATUS_APPROVED if allow else GlobalMcpApprovalRequest.STATUS_REJECTED
    approval.human_decided_at = timezone.now()
    approval.decided_by_sub = actor_sub
    approval.save(update_fields=['status', 'human_decided_at', 'decided_by_sub'])
    GlobalMcpApprovalDecisionAudit.objects.create(
        approval=approval,
        event='approve' if allow else 'deny',
        actor_sub=actor_sub,
    )
    if approval.kind == GlobalMcpApprovalRequest.KIND_GRANT and allow:
        from apps.global_mcp.grants import apply_grant_approval

        apply_grant_approval(approval)
    return approval.status


def apply_form_decision(approval: GlobalMcpApprovalRequest, result: dict | None) -> str:
    """Map an elicitation answer onto the approval row. Returns approved, denied, or pending."""
    if not isinstance(result, dict):
        return 'pending'
    if str(result.get('action') or '').lower() in {'decline', 'cancel', 'dismiss'}:
        return decide_page(approval, actor_sub=approval.owner_sub, allow=False)
    content = result.get('content') if isinstance(result.get('content'), dict) else {}
    decision = str(content.get('decision') or result.get('decision') or '').lower()
    if decision == 'approve':
        return decide_page(approval, actor_sub=approval.owner_sub, allow=True)
    if decision == 'deny':
        return decide_page(approval, actor_sub=approval.owner_sub, allow=False)
    return 'pending'


def approval_state(approval_id: str) -> str | None:
    row = GlobalMcpApprovalRequest.objects.filter(pk=approval_id).first()
    if row is None:
        return None
    if row.status == GlobalMcpApprovalRequest.STATUS_PENDING and row.expires_at <= timezone.now():
        return 'expired'
    if row.status == GlobalMcpApprovalRequest.STATUS_APPROVED:
        return 'approved'
    if row.status == GlobalMcpApprovalRequest.STATUS_REJECTED:
        return 'denied'
    if row.status == GlobalMcpApprovalRequest.STATUS_EXPIRED:
        return 'expired'
    return None
