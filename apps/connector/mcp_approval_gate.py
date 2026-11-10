"""MCP tools/call approval enforcement for the ai-service gateway."""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import secrets
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
from apps.connector.mcp_approvals import DecideResult

from apps.connector.mcp_call_audit import build_call_audit_log
from apps.connector.mcp_company_label import resolve_company_label
from apps.connector.mcp_identity import agent_is_revoked
from apps.connector.mcp_company_id import strict_numeric_company_id
from apps.connector.mcp_setup_context import approval_assertion_context_from_agent_claims

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GateOutcome:
    proceed: bool
    response: JsonResponse | None = None
    log: dict[str, Any] | None = None


def access_mode_from_claims(agent_claims: dict[str, Any]) -> str:
    return str(agent_claims.get('mcp_access') or 'ask')


def _log_result_from_decide(decided: DecideResult, *, fallback: str) -> str:
    """Map Identity decide response to stable gateway log tokens (activity outcomes)."""
    if not decided.ok:
        return 'error'
    ap = str(decided.approval_status or '').strip().lower()
    aud = str(decided.audit_status or '').strip().lower()
    # HTTP 200 JSON can still be a non-success human flow (e.g. pending); never map that to authority success.
    if ap == 'approved' and aud in {'', 'ok', 'approved', 'success'}:
        return 'identity_approved'
    if aud in {'pending', 'pending_approval'}:
        return aud
    if aud in {'denied', 'client_denied', 'expired', 'error'}:
        return aud
    if ap in {'denied'}:
        return 'denied'
    return aud or fallback


def _arguments_hash(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()


def _connection_id(request: HttpRequest) -> str:
    return str(
        request.headers.get('Mcp-Session-Id') or request.headers.get('MCP-Session-Id') or ''
    ).strip()


def _client_elicitation_modes(request: HttpRequest, params: dict[str, Any] | None) -> tuple[bool, bool]:
    """Form elicitation (Shellui buttons) and URL elicitation (spec ``elicitation.url``)."""
    from apps.connector.mcp_protocol import (
        elicitation_modes_from_capabilities,
        session_elicitation_supported,
        session_url_elicitation_supported,
    )

    if isinstance(params, dict):
        meta = params.get('_meta')
        if isinstance(meta, dict) and 'io.modelcontextprotocol/clientCapabilities' in meta:
            return elicitation_modes_from_capabilities(meta.get('io.modelcontextprotocol/clientCapabilities'))
    connection_id = _connection_id(request)
    if not connection_id:
        return False, False
    return session_elicitation_supported(connection_id), session_url_elicitation_supported(connection_id)


def _form_consent(params: dict[str, Any] | None) -> str | None:
    """In-chat form result: ``approve`` or ``deny``. None when the client has not answered."""
    if not isinstance(params, dict):
        return None
    responses = params.get('inputResponses')
    if not isinstance(responses, dict):
        return None
    block = responses.get('approval')
    if not isinstance(block, dict):
        return None
    action = str(block.get('action') or '').strip().lower()
    content = block.get('content') if isinstance(block.get('content'), dict) else {}
    decision = str(content.get('decision') or '').strip().lower()
    if action in {'decline', 'cancel'} or decision in {'deny', 'decline'}:
        return 'deny'
    if action == 'accept' and decision in {'', 'approve', 'allow'}:
        return 'approve'
    return None


def _url_elicitation_action(params: dict[str, Any] | None) -> str | None:
    """``inputResponses.approval.action`` from a 2026-07-28 URL elicitation retry."""
    if not isinstance(params, dict):
        return None
    responses = params.get('inputResponses')
    if not isinstance(responses, dict):
        return None
    block = responses.get('approval')
    if not isinstance(block, dict):
        return None
    action = str(block.get('action') or '').strip().lower()
    if action in {'accept', 'decline', 'cancel'}:
        return action
    return None


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
    meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
    m = str(method or meta.get('method') or 'GET').upper()
    # Registry `_meta` is authoritative when present. Annotation hints are the
    # fallback for catalogs that never carried `_meta` (and for DELETE, which is
    # always destructive). A presentation hint must not upgrade a non-destructive
    # PUT/PATCH into a destructive call.
    if 'read_only' in meta:
        read_only = bool(meta.get('read_only'))
    else:
        read_only = bool(ann.get('readOnlyHint'))
    if m in {'GET', 'HEAD', 'OPTIONS'}:
        read_only = True
    if m == 'DELETE':
        destructive = True
    elif 'destructive' in meta:
        destructive = bool(meta.get('destructive'))
    else:
        destructive = bool(ann.get('destructiveHint'))
    if read_only and m != 'DELETE':
        destructive = False
    return read_only, destructive


def _agent_display_name(agent_claims: dict[str, Any]) -> str:
    name = str(agent_claims.get('agent_name') or '').strip()
    if name:
        return name
    agent_id = str(agent_claims.get('agent_id') or 'Agent')
    return f'Agent {agent_id[:8]}'


def _expires_or_none(*candidates: object) -> str | None:
    for raw in candidates:
        if raw is None or isinstance(raw, bool):
            continue
        text = str(raw).strip()
        if text and not any(ch in text for ch in '\r\n'):
            return text[:80]
    return None


def pending_approval_payload(
    *,
    tool_name: str,
    approval_id: str,
    approval_url: str,
    expires_at: str | None,
) -> dict[str, Any]:
    return {
        'status': 'pending',
        'approval_id': approval_id,
        'expires_at': expires_at,
        'approval_url': approval_url,
        'instruction': copy.pending_agent_instruction(tool_name=tool_name),
    }


def pending_approval_text(payload: dict[str, Any]) -> str:
    instruction = str(payload.get('instruction') or '').strip()
    url = str(payload.get('approval_url') or '').strip()
    body = json.dumps(payload, sort_keys=True, default=str)
    return f'Approval pending. {instruction} Link: {url}\n{body}'


def build_elicitation_meta(
    *,
    tool_name: str,
    destructive: bool,
    agent_claims: dict[str, Any],
    approval_id: str,
    tool_count: int = 1,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from apps.connector.mcp_discovery import arguments_preview

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
    preview = arguments_preview(arguments)
    if preview:
        body = f'{body} {preview}'
    buttons: dict[str, str] = {'allow': 'Allow', 'deny': 'Deny'}
    if not destructive:
        buttons['session_allow'] = 'Allow for this session'
    ctx = approval_assertion_context_from_agent_claims(agent_claims)
    session_seconds = (
        ctx.mcp_session_ttl_seconds if ctx.setup_flow and ctx.mcp_session_ttl_seconds else copy.SESSION_SECONDS
    )
    payload: dict[str, Any] = {
        'approval_id': approval_id,
        'status': 'pending',
        'elicitation': {
            'title': title,
            'body': body,
            'buttons': buttons,
            'session_seconds': session_seconds,
        },
        'settings_url': approvals.approval_settings_url(approval_id),
        'approvals_list_url': approvals.approval_settings_url(),
    }
    if not destructive:
        payload['elicitation']['session_helper'] = copy.session_helper_text(seconds=session_seconds)
    return payload


def _approval_result(
    req_id: Any,
    *,
    text: str,
    meta: dict[str, Any],
    is_error: bool = True,
    structured: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> JsonResponse:
    result: dict[str, Any] = {
        'content': [{'type': 'text', 'text': text}],
        'isError': is_error,
        '_meta': meta,
    }
    if structured is not None:
        result['structuredContent'] = structured
    if extra:
        result.update(extra)
    return JsonResponse(McpServer._result(req_id, result))


def _audit_status_from_log_result(log_result: str) -> tuple[int, bool | None]:
    lr = str(log_result or '').strip().lower()
    if lr in {'denied', 'client_denied'}:
        return 403, True
    if lr in {'pending', 'pending_approval'}:
        return 202, None
    if lr in {'expired'}:
        return 410, True
    if lr in {'error'}:
        return 500, True
    if lr in {'success', 'approved', 'client_allowed', 'client_session_allowed', 'identity_approved'}:
        return 200, False
    return 200, None


def _log_entry(
    *,
    agent_claims: dict[str, Any],
    service: str,
    export_name: str,
    tool: dict[str, Any] | None,
    method: str,
    path: str,
    log_result: str,
    approval_id: str | None = None,
) -> dict[str, Any]:
    status, is_error = _audit_status_from_log_result(log_result)
    row = build_call_audit_log(
        agent_claims=agent_claims,
        service_id=service,
        export_name=export_name,
        tool=tool,
        method=method,
        path=path,
        log_result=str(log_result),
        status=status,
        is_error=is_error,
        approval_id=approval_id,
    )
    row['_mcp_audit_ready'] = True
    row['duration_ms'] = 0
    return row


def _create_failed_outcome(req_id: Any) -> GateOutcome:
    reason = approvals.take_approval_create_error()
    text = copy.approval_create_failed_text(reason)
    code = reason or 'unavailable'
    return GateOutcome(
        proceed=False,
        response=_approval_result(
            req_id,
            text=text,
            meta={'status': 'error', 'error': code},
            structured={'status': 'error', 'error': code, 'message': text},
        ),
    )


def _consume_approved_outcome(
    req_id: Any,
    *,
    approval_id: str,
    approval_payload: dict[str, Any],
    agent_claims: dict[str, Any],
    service_id: str,
    export_name: str,
    tool: dict[str, Any] | None,
    method: str,
    path: str,
) -> GateOutcome:
    if approval_id:
        consumed = approvals.approval_consume_detail(approval_id, approval_payload)
        if consumed.consumed:
            return GateOutcome(
                proceed=True,
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result='identity_approved',
                    approval_id=approval_id,
                ),
            )
        if consumed.already_consumed:
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text=copy.expired_text(),
                    meta={'shellui_approval': {'status': 'expired', 'consumed': False}},
                ),
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result='error',
                    approval_id=approval_id,
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
            export_name=export_name,
            tool=tool,
            method=method,
            path=path,
            log_result='expired',
        ),
    )


def _pending_approval_outcome(
    req_id: Any,
    *,
    agent_claims: dict[str, Any],
    export_name: str,
    service_id: str,
    tool: dict[str, Any] | None,
    method: str,
    path: str,
    arguments: dict[str, Any],
    approval_payload: dict[str, Any],
    approval_id: str,
    created: dict[str, Any] | None,
    destructive: bool,
    form_mode: bool,
    url_mode: bool,
    channel: str,
) -> GateOutcome:
    created_url = str(created.get('approval_url') or '') if isinstance(created, dict) else ''
    created_path = str(created.get('fallback_path') or '') if isinstance(created, dict) else ''
    created_expires = created.get('expires_at') if isinstance(created, dict) else None
    expires_at = _expires_or_none(created_expires, approval_payload.get('approval_expires_at'))
    page_url = approvals.resolve_approval_url(
        approval_id,
        approval_url=created_url or str(approval_payload.get('approval_url_field') or ''),
        fallback_path=created_path or str(approval_payload.get('approval_fallback_path') or ''),
    )
    approvals.remember_approval(
        approval_id,
        approval_payload,
        expires_at=expires_at or '',
        approval_url=page_url,
    )
    structured = pending_approval_payload(
        tool_name=export_name,
        approval_id=approval_id,
        approval_url=page_url,
        expires_at=expires_at,
    )
    shellui: dict[str, Any] = {
        'approval_id': approval_id,
        'status': 'pending',
        'expires_at': expires_at,
        'approval_url': page_url,
        'settings_url': approvals.approval_settings_url(approval_id),
        'approvals_list_url': approvals.approval_settings_url(),
        'channel': channel,
    }
    if channel == 'form':
        message = copy.form_approval_message(tool_name=export_name)
        structured = {
            'status': 'pending',
            'approval_id': approval_id,
            'expires_at': expires_at,
            'channel': 'form',
            'instruction': copy.form_approval_instruction(tool_name=export_name),
        }
        extra = {
            'resultType': 'input_required',
            'requestState': secrets.token_urlsafe(24),
            'inputRequests': {
                'approval': {
                    'method': 'elicitation/create',
                    'params': {
                        'mode': 'form',
                        'message': message,
                        'requestedSchema': {
                            'type': 'object',
                            'properties': {
                                'decision': {
                                    'type': 'string',
                                    'title': 'Decision',
                                    'oneOf': [
                                        {'const': 'approve', 'title': 'Approve'},
                                        {'const': 'deny', 'title': 'Deny'},
                                    ],
                                }
                            },
                            'required': ['decision'],
                        },
                    },
                }
            },
        }
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=f'{message} {structured["instruction"]}',
                meta={'shellui_approval': {**shellui, 'channel': 'form'}},
                is_error=False,
                structured=structured,
                extra=extra,
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                export_name=export_name,
                tool=tool,
                method=method,
                path=path,
                log_result='pending_approval',
                approval_id=approval_id,
            ),
        )
    extra: dict[str, Any] | None = None
    if url_mode and channel != 'form':
        # Current spec (2026-07-28) delivers URL elicitation as an InputRequiredResult
        # on tools/call. elicitationId is required by @modelcontextprotocol/sdk 1.32.2
        # URL params and is ignored by clients that only read mode, url, and message.
        extra = {
            'resultType': 'input_required',
            'requestState': secrets.token_urlsafe(24),
            'inputRequests': {
                'approval': {
                    'method': 'elicitation/create',
                    'params': {
                        'mode': 'url',
                        'elicitationId': secrets.token_urlsafe(16),
                        'url': page_url,
                        'message': copy.url_elicitation_message(tool_name=export_name),
                    },
                }
            },
        }
    return GateOutcome(
        proceed=False,
        response=_approval_result(
            req_id,
            text=pending_approval_text(structured),
            meta={'shellui_approval': shellui},
            is_error=False,
            structured=structured,
            extra=extra,
        ),
        log=_log_entry(
            agent_claims=agent_claims,
            service=service_id,
            export_name=export_name,
            tool=tool,
            method=method,
            path=path,
            log_result='pending_approval',
            approval_id=approval_id,
        ),
    )


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
    allow_destructive_flag = bool(agent_claims.get('mcp_destructive'))
    if destructive and allow_destructive_flag:
        logger.info(
            'MCP gateway ignoring mcp_destructive for destructive tool (approval required): company_id=%s agent_id=%s export=%s',
            agent_claims.get('company_id'),
            agent_claims.get('agent_id'),
            export_name,
        )
    decision = decide_write(
        method=method,
        access_mode=access,
        destructive=destructive,
        allow_destructive_without_asking=(allow_destructive_flag and not destructive),
        tool_read_only=read_only,
    )
    connection_id = _connection_id(request)
    agent_id = str(agent_claims.get('agent_id') or '')
    cid = strict_numeric_company_id(agent_claims.get('company_id'))
    if cid is None:
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text='Invalid company scope.',
                meta={'status': 'denied'},
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                export_name=export_name,
                tool=tool,
                method=method,
                path=path,
                log_result='denied',
            ),
        )
    company_id = cid

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
                export_name=export_name,
                tool=tool,
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
        'arguments_hash': args_hash,
        '_agent_claims': agent_claims,
        '_arguments_summary': approvals.approval_arguments_summary(arguments),
    }

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
                export_name=export_name,
                tool=tool,
                method=method,
                path=path,
                log_result=log_result,
                approval_id=client_approval_id,
            ),
        )

    if approvals.session_grant_covers_write(
        approval_payload,
        connection_id=connection_id,
        is_destructive=destructive,
    ):
        if agent_is_revoked(agent_id, company_id):
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text='Agent access was revoked.',
                    meta={'status': 'denied'},
                ),
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result='denied',
                ),
            )
        return GateOutcome(proceed=True)

    # Identity rejects session allow on destructive rows (409). Do not consume or
    # record session_used; fall through so a duplicate executed row stays failed.
    if client_decision == 'session_allow' and client_approval_id and not destructive:
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
            log_result = _log_result_from_decide(decided, fallback='client_session_allowed')
            return GateOutcome(
                proceed=True,
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result=log_result,
                ),
            )

    state = approvals.approval_state(approval_payload)
    if state == 'expired':
        if client_approval_id:
            duplicate = approvals.approval_consume_detail(client_approval_id, approval_payload)
            if duplicate.already_consumed:
                # Identity #138 accepts failed plus the executed approval id. Denial must not
                # drop that id, and this is not a second execution.
                return GateOutcome(
                    proceed=False,
                    response=_approval_result(
                        req_id,
                        text=copy.expired_text(),
                        meta={'shellui_approval': {'status': 'expired', 'consumed': False}},
                    ),
                    log=_log_entry(
                        agent_claims=agent_claims,
                        service=service_id,
                        export_name=export_name,
                        tool=tool,
                        method=method,
                        path=path,
                        log_result='error',
                        approval_id=client_approval_id,
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
                export_name=export_name,
                tool=tool,
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
                export_name=export_name,
                tool=tool,
                method=method,
                path=path,
                log_result='denied',
                approval_id=client_approval_id,
            ),
        )
    if state == 'approved':
        approval_id = str(approval_payload.get('approval_id') or client_approval_id or '')
        return _consume_approved_outcome(
            req_id,
            approval_id=approval_id,
            approval_payload=approval_payload,
            agent_claims=agent_claims,
            service_id=service_id,
            export_name=export_name,
            tool=tool,
            method=method,
            path=path,
        )

    if client_decision == 'allow' and client_approval_id:
        decided = _decide(client_approval_id, 'allow')
        if decided.ok and approvals.approval_consume(client_approval_id, approval_payload):
            log_result = _log_result_from_decide(decided, fallback='client_allowed')
            return GateOutcome(
                proceed=True,
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result=log_result,
                ),
            )

    from apps.connector.mcp_approval_channel import CHANNEL_FORM, approval_channel
    from apps.connector.mcp_protocol import session_client_name

    form_mode, url_mode = _client_elicitation_modes(request, params)
    channel = approval_channel(
        destructive=destructive,
        company_id=company_id,
        form_supported=form_mode,
    )
    url_action = _url_elicitation_action(params)
    form_decision = _form_consent(params) if channel == CHANNEL_FORM else None
    if channel != CHANNEL_FORM and url_action in {'decline', 'cancel'}:
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=copy.elicitation_declined_text(tool_name=export_name),
                meta={'shellui_approval': {'status': 'denied', 'decision': url_action}},
                structured={
                    'status': 'denied',
                    'message': copy.elicitation_declined_text(tool_name=export_name),
                },
            ),
            log=_log_entry(
                agent_claims=agent_claims,
                service=service_id,
                export_name=export_name,
                tool=tool,
                method=method,
                path=path,
                log_result='client_denied',
                approval_id=client_approval_id,
            ),
        )

    created: dict[str, Any] | None = None
    approval_id = client_approval_id or str(approval_payload.get('approval_id') or '')
    if state != 'pending' or not approval_id:
        approvals.take_approval_create_error()
        created = approvals.create_approval_request(approval_payload, is_destructive=destructive)
        approval_id = str(created.get('id') or '') if created else ''
        if not approval_id:
            return _create_failed_outcome(req_id)

    if channel == CHANNEL_FORM and form_decision in {'approve', 'deny'}:
        client_name = session_client_name(_connection_id(request))
        identity_decision = 'allow' if form_decision == 'approve' else 'deny'
        decided = _decide(approval_id, identity_decision)
        logger.info(
            'MCP in-chat approval company_id=%s agent_id=%s tool=%s client_name=%s decision=%s identity_ok=%s',
            company_id,
            agent_id,
            export_name,
            client_name or 'unknown',
            identity_decision,
            decided.ok,
        )
        if form_decision == 'deny':
            if not decided.ok:
                return GateOutcome(
                    proceed=False,
                    response=_approval_result(
                        req_id,
                        text=copy.form_consent_failed_text(),
                        meta={'status': 'error', 'channel': 'form', 'approval_id': approval_id},
                    ),
                )
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text=copy.after_deny_text(tool_name=export_name),
                    meta={'shellui_approval': {'status': 'denied', 'channel': 'form', 'approval_id': approval_id}},
                ),
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result='client_denied',
                    approval_id=approval_id,
                ),
            )
        if decided.ok and approvals.approval_consume_detail(approval_id, approval_payload).consumed:
            return GateOutcome(
                proceed=True,
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result=_log_result_from_decide(decided, fallback='client_allowed'),
                    approval_id=approval_id,
                ),
            )
        return GateOutcome(
            proceed=False,
            response=_approval_result(
                req_id,
                text=copy.form_consent_failed_text(),
                meta={'status': 'error', 'channel': 'form'},
            ),
        )

    if channel != CHANNEL_FORM and url_action == 'accept' and url_mode:
        polled = approvals.poll_approval_state(
            approval_payload,
            timeout_seconds=approvals.elicitation_wait_seconds(),
        )
        if polled == 'approved':
            return _consume_approved_outcome(
                req_id,
                approval_id=str(approval_payload.get('approval_id') or approval_id),
                approval_payload=approval_payload,
                agent_claims=agent_claims,
                service_id=service_id,
                export_name=export_name,
                tool=tool,
                method=method,
                path=path,
            )
        if polled == 'denied':
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text=copy.after_deny_text(tool_name=export_name),
                    meta={'shellui_approval': {'status': 'denied', 'approval_id': approval_id}},
                ),
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result='denied',
                    approval_id=approval_id,
                ),
            )
        if polled == 'expired':
            return GateOutcome(
                proceed=False,
                response=_approval_result(
                    req_id,
                    text=copy.expired_text(),
                    meta={'shellui_approval': {'status': 'expired', 'approval_id': approval_id}},
                ),
                log=_log_entry(
                    agent_claims=agent_claims,
                    service=service_id,
                    export_name=export_name,
                    tool=tool,
                    method=method,
                    path=path,
                    log_result='expired',
                    approval_id=approval_id,
                ),
            )

    return _pending_approval_outcome(
        req_id,
        agent_claims=agent_claims,
        export_name=export_name,
        service_id=service_id,
        tool=tool,
        method=method,
        path=path,
        arguments=arguments,
        approval_payload=approval_payload,
        approval_id=approval_id,
        created=created,
        destructive=destructive,
        form_mode=form_mode,
        url_mode=url_mode,
        channel=channel,
    )
