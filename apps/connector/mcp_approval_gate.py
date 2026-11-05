"""MCP tools/call approval enforcement for the ai-service gateway."""

from __future__ import annotations

import contextvars
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from django.http import HttpRequest, JsonResponse
from shellui_django.mcp.server import McpServer
from shellui_django.mcp.write_gate import WriteGateDecision, decide_write

_approval_bypass: contextvars.ContextVar[bool] = contextvars.ContextVar('mcp_approval_bypass', default=False)


def bypass_shellui_write_gate() -> contextvars.Token:
    return _approval_bypass.set(True)


def reset_shellui_write_gate(token: contextvars.Token) -> None:
    _approval_bypass.reset(token)


def patched_decide_write(**kwargs: Any) -> WriteGateDecision:
    if _approval_bypass.get():
        return WriteGateDecision(allowed=True)
    return decide_write(**kwargs)

from apps.connector import mcp_approval_copy as copy
from apps.connector import mcp_approvals as approvals
from apps.connector.mcp_company_label import resolve_company_label


@dataclass(frozen=True, slots=True)
class GateOutcome:
    proceed: bool
    response: JsonResponse | None = None
    log: dict[str, Any] | None = None


def access_mode_from_claims(agent_claims: dict[str, Any]) -> str:
    return str(agent_claims.get('mcp_access') or 'ask')


def _arguments_hash(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()


def _connection_id(request: HttpRequest) -> str:
    return str(
        request.headers.get('Mcp-Session-Id') or request.headers.get('MCP-Session-Id') or ''
    ).strip()


def _client_elicitation_supported(request: HttpRequest) -> bool:
    from apps.connector.mcp_protocol import session_elicitation_supported

    connection_id = _connection_id(request)
    if not connection_id:
        return False
    return session_elicitation_supported(connection_id)


def _shellui_meta(params: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(params, dict):
        return {}
    meta = params.get('_meta')
    return meta if isinstance(meta, dict) else {}


def parse_client_decision(params: dict[str, Any] | None) -> tuple[str | None, str | None]:
    meta = _shellui_meta(params)
    block = meta.get('shellui_approval')
    if not isinstance(block, dict):
        return None, None
    decision = str(block.get('decision') or '').strip().lower()
    approval_id = str(block.get('approval_id') or '').strip() or None
    if decision in {'allow', 'deny', 'session_allow'}:
        return decision, approval_id
    return None, approval_id


def tool_traits_from_export(tool: dict[str, Any] | None, *, method: str = 'GET') -> tuple[bool, bool]:
    if not isinstance(tool, dict):
        return False, method.upper() in {'GET', 'HEAD', 'OPTIONS'}
    ann = tool.get('annotations') if isinstance(tool.get('annotations'), dict) else {}
    read_only = bool(ann.get('readOnlyHint'))
    destructive = bool(ann.get('destructiveHint'))
    meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
    if meta.get('read_only') is True:
        read_only = True
    if meta.get('destructive') is True:
        destructive = True
    m = str(method or meta.get('method') or 'GET').upper()
    if m in {'GET', 'HEAD', 'OPTIONS'}:
        read_only = True
    return read_only, destructive


def _agent_display_name(agent_claims: dict[str, Any]) -> str:
    name = str(agent_claims.get('agent_name') or '').strip()
    if name:
        return name
    agent_id = str(agent_claims.get('agent_id') or 'Agent')
    return f'Agent {agent_id[:8]}'


def build_elicitation_meta(
    *,
    tool_name: str,
    destructive: bool,
    agent_claims: dict[str, Any],
    approval_id: str,
    short_action_summary: str = '',
    tool_count: int = 1,
) -> dict[str, Any]:
    agent_name = _agent_display_name(agent_claims)
    company_name = resolve_company_label(agent_claims)
    title = copy.approval_title(tool_name=tool_name, destructive=destructive)
    body = (
        copy.approval_batch_body(
            agent_name=agent_name,
            tool_name=tool_name,
            company_name=company_name,
            tool_count=tool_count,
        )
        if tool_count > 1
        else copy.approval_body(agent_name=agent_name, tool_name=tool_name, company_name=company_name)
    )
    buttons: dict[str, str] = {'allow': 'Allow', 'deny': 'Deny'}
    if not destructive:
        buttons['session_allow'] = 'Allow for this session'
    payload: dict[str, Any] = {
        'approval_id': approval_id,
        'status': 'pending',
        'elicitation': {
            'title': title,
            'body': body,
            'buttons': buttons,
            'session_seconds': copy.SESSION_SECONDS,
        },
        'settings_url': approvals.approval_settings_url(approval_id),
        'approvals_list_url': approvals.approval_settings_url(),
    }
    if short_action_summary:
        payload['elicitation']['detail'] = short_action_summary
    if not destructive:
        payload['elicitation']['session_helper'] = copy.session_helper_text()
    return payload


def _approval_result(
    req_id: Any,
    *,
    text: str,
    meta: dict[str, Any],
    is_error: bool = True,
) -> JsonResponse:
    return JsonResponse(
        McpServer._result(
            req_id,
            {
                'content': [{'type': 'text', 'text': text}],
                'isError': is_error,
                '_meta': meta,
            },
        )
    )


def _log_entry(
    *,
    agent_claims: dict[str, Any],
    service: str,
    tool: str,
    method: str,
    path: str,
    log_result: str,
) -> dict[str, Any]:
    return {
        'agent_id': agent_claims.get('agent_id'),
        'company_id': agent_claims.get('company_id'),
        'service': service,
        'tool': tool,
        'method': method,
        'path': path,
        'status': 200,
        'is_error': log_result not in {'success', 'client_allowed', 'client_session_allowed', 'approved'},
        'log_result': log_result,
    }


def enforce_tool_call_approval(
    request: HttpRequest,
    req_id: Any,
    *,
    params: dict[str, Any],
    agent_claims: dict[str, Any],
    export_name: str,
    service_id: str,
    tool: dict[str, Any] | None,
    method: str,
    path: str,
    arguments: dict[str, Any],
) -> GateOutcome:
    read_only, destructive = tool_traits_from_export(tool, method=method)
    access = access_mode_from_claims(agent_claims)
    decision = decide_write(
        method=method,
        access_mode=access,
        destructive=destructive,
        allow_destructive_without_asking=bool(agent_claims.get('mcp_destructive')),
        tool_read_only=read_only,
    )
    connection_id = _connection_id(request)
    agent_id = str(agent_claims.get('agent_id') or '')
    company_id = int(agent_claims.get('company_id') or 0)

    if not decision.needs_approval and decision.allowed:
        return GateOutcome(proceed=True)

    if not decision.needs_approval and not decision.allowed:
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=decision.reason or 'Forbidden',
                meta={'status': 'denied'},
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                tool=export_name,
                method=method,
                path=path,
                log_result='denied',
            ),
        )

    args_hash = _arguments_hash(arguments)
    approval_payload: dict[str, Any] = {
        'agent_id': agent_id,
        'company_id': company_id,
        'service': service_id,
        'action': export_name,
        'arguments': arguments,
        'arguments_hash': args_hash,
        'path': path,
        'method': method,
    }

    if approvals.session_grant_covers_write(
        approval_payload,
        connection_id=connection_id,
        is_destructive=destructive,
    ):
        return GateOutcome(proceed=True)

    client_decision, client_approval_id = parse_client_decision(params)
    actor_email = str(agent_claims.get('email') or '').strip() or None

    def _decide(approval_id: str, decision: str) -> approvals.DecideResult:
        return approvals.decide_approval(
            approval_id=approval_id,
            payload=approval_payload,
            decision=decision,
            connection_id=connection_id,
            actor_email=actor_email,
        )

    if client_decision == 'deny' and client_approval_id:
        decided = _decide(client_approval_id, 'deny')
        log_result = decided.audit_status or 'client_denied'
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=copy.after_deny_text(tool_name=export_name),
                meta={'shellui_approval': {'status': 'denied', 'decision': 'deny'}},
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                tool=export_name,
                method=method,
                path=path,
                log_result=log_result,
            ),
        )

    if client_decision == 'session_allow' and client_approval_id:
        decided = _decide(client_approval_id, 'allow_session')
        if decided.status_code == 409 or not decided.ok:
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text=copy.approval_title(tool_name=export_name, destructive=destructive),
                    meta={'shellui_approval': {'status': 'pending', 'session_allow': False}},
                ),
            )
        if approvals.approval_consume(client_approval_id, approval_payload):
            log_result = decided.audit_status or 'client_session_allowed'
            return GateOutcome(
                proceed=True,
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    tool=export_name,
                    method=method,
                    path=path,
                    log_result=log_result,
                ),
            )

    state = approvals.approval_state(approval_payload)
    if state == 'expired':
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=copy.expired_text(),
                meta={'shellui_approval': {'status': 'expired'}},
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                tool=export_name,
                method=method,
                path=path,
                log_result='expired',
            ),
        )
    if state == 'denied':
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=copy.after_deny_text(tool_name=export_name),
                meta={'shellui_approval': {'status': 'denied'}},
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                tool=export_name,
                method=method,
                path=path,
                log_result='denied',
            ),
        )
    if state == 'approved':
        approval_id = str(approval_payload.get('approval_id') or client_approval_id or '')
        if approval_id and approvals.approval_consume(approval_id, approval_payload):
            log_result = 'approved'
            return GateOutcome(
                proceed=True,
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    tool=export_name,
                    method=method,
                    path=path,
                    log_result=log_result,
                ),
            )
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=copy.expired_text(),
                meta={'shellui_approval': {'status': 'expired'}},
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                tool=export_name,
                method=method,
                path=path,
                log_result='expired',
            ),
        )

    if client_decision == 'allow' and client_approval_id:
        decided = _decide(client_approval_id, 'allow')
        if decided.ok and approvals.approval_consume(client_approval_id, approval_payload):
            log_result = decided.audit_status or 'client_allowed'
            return GateOutcome(
                proceed=True,
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    tool=export_name,
                    method=method,
                    path=path,
                    log_result=log_result,
                ),
            )

    if state == 'pending':
        approval_id = client_approval_id or str(approval_payload.get('approval_id') or '')
        if not approval_id:
            created = approvals.create_approval_request(approval_payload, is_destructive=destructive)
            approval_id = str(created.get('id') or '') if created else ''
        if not approval_id:
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text='Approval unavailable.',
                    meta={'status': 'error'},
                ),
            )
        if _client_elicitation_supported(request):
            meta = build_elicitation_meta(
                tool_name=export_name,
                destructive=destructive,
                agent_claims=agent_claims,
                approval_id=approval_id,
            )
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text=meta['elicitation']['title'],
                    meta={'shellui_approval': meta},
                ),
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    tool=export_name,
                    method=method,
                    path=path,
                    log_result='pending',
                ),
            )
        settings_url = approvals.approval_settings_url(approval_id)
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=copy.fallback_pending_text(settings_url=settings_url),
                meta={
                    'shellui_approval': {
                        'approval_id': approval_id,
                        'status': 'pending',
                        'settings_url': settings_url,
                        'approvals_list_url': approvals.approval_settings_url(),
                    }
                },
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                tool=export_name,
                method=method,
                path=path,
                log_result='pending',
            ),
        )

    created = approvals.create_approval_request(approval_payload, is_destructive=destructive)
    if not created:
        return GateOutcome(
            proceed=False,
            response=_approval_result(req_id, text='Approval unavailable.', meta={'status': 'error'}),
        )
    approval_id = str(created['id'])
    if _client_elicitation_supported(request):
        meta = build_elicitation_meta(
            tool_name=export_name,
            destructive=destructive,
            agent_claims=agent_claims,
            approval_id=approval_id,
        )
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=meta['elicitation']['title'],
                meta={'shellui_approval': meta},
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                tool=export_name,
                method=method,
                path=path,
                log_result='pending',
            ),
        )
    settings_url = approvals.approval_settings_url(approval_id)
    return GateOutcome(
        proceed=False,
        response=_approval_result(
            req_id,
            text=copy.fallback_pending_text(settings_url=settings_url),
            meta={
                'shellui_approval': {
                    'approval_id': approval_id,
                    'status': 'pending',
                    'settings_url': settings_url,
                }
            },
        ),
        log=_log_entry(
            agent_claims=agent_claims,
            service=service_id,
            tool=export_name,
            method=method,
            path=path,
            log_result='pending',
        ),
    )
