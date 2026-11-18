"""Global plane call logs. company_id stays null. owner_sub is the Shellui account."""

from __future__ import annotations

import uuid

from apps.connector.mcp_call_store import redact_arguments_for_log, safe_error_message
from apps.connector.models import McpCallLog


def write_global_call(
    *,
    agent_id: str,
    agent_name: str,
    owner_sub: str,
    user_email: str,
    tool_name: str,
    arguments: dict | None,
    status: str,
    status_code: int = 200,
    error_code: str = '',
    error_message: str = '',
    correlation_id: uuid.UUID | None = None,
    global_company_id: str = '',
    regional_company_id: str = '',
    region: str = '',
    approval_id: str = '',
    approval_channel: str = 'none',
    duration_ms: int = 0,
) -> McpCallLog | None:
    try:
        return McpCallLog.objects.create(
            company_id=None,
            plane=McpCallLog.PLANE_GLOBAL,
            owner_sub=(owner_sub or '')[:255],
            agent_id=(agent_id or '')[:128],
            agent_name=(agent_name or '')[:200],
            user_email=(user_email or '')[:254],
            service='saas' if str(tool_name).startswith('saas_') else 'ai',
            tool_name=(tool_name or '')[:255],
            arguments_redacted=redact_arguments_for_log(arguments),
            status=status if status in dict(McpCallLog.STATUSES) else McpCallLog.STATUS_ERROR,
            status_code=max(0, int(status_code)),
            error_code=(error_code or '')[:64],
            error_message=safe_error_message(error_message),
            global_agent_id=(agent_id or '')[:64],
            global_company_id=(global_company_id or '')[:64],
            correlation_id=correlation_id,
            regional_company_id=(regional_company_id or '')[:64],
            region=(region or '')[:32],
            approval_id=(approval_id or '')[:64],
            approval_channel=approval_channel if approval_channel in {'form', 'link', 'none'} else 'none',
            duration_ms=max(0, int(duration_ms)),
            outcome=status if status in {'allowed', 'denied', 'waiting_approval', 'failed'} else 'failed',
            access_kind='read' if str(tool_name).startswith('saas_get_') or str(tool_name).startswith('saas_list_') else 'write',
        )
    except Exception:
        return None
