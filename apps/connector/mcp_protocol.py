"""MCP Streamable HTTP compliance helpers (spec revision 2025-06-18).

``shellui-django`` 0.4.0 ``McpServer`` / ``AggregatingMcpServer`` omit ``serverInfo`` on
``initialize`` and do not handle ``notifications/initialized``. This module patches those
gaps for the ai-service gateway without changing auth or tenant isolation.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from shellui_django.mcp.gateway import AggregatingMcpServer

from apps.connector.mcp_call_log import begin_mcp_tool_call_timer, reset_mcp_tool_call_timer
from apps.connector.mcp_tool_presentation import shellui_gateway_instructions
from shellui_django.mcp.rate_limit import check_agent_rate_limit
from shellui_django.mcp.server import McpServer

# Newest first; negotiation picks the client version when it appears in this tuple.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    '2025-06-18',
    '2025-03-26',
    '2024-11-05',
)

MCP_SERVER_NAME = 'shellui-ai-mcp-gateway'
MCP_SERVER_VERSION = '0.1.0'
MCP_SESSION_CACHE_PREFIX = 'mcp_gateway:session:'
MCP_SESSION_TTL_SECONDS = 86400
MCP_TOOLS_PAGE_SIZE = 200

_SUPPORTED_PROTOCOL_SET = frozenset(SUPPORTED_PROTOCOL_VERSIONS)


def negotiate_protocol_version(client_version: str | None) -> str:
    requested = str(client_version or '').strip()
    if requested in _SUPPORTED_PROTOCOL_SET:
        return requested
    return SUPPORTED_PROTOCOL_VERSIONS[0]


def server_capabilities() -> dict[str, Any]:
    return {'tools': {}}


def build_initialize_result(
    server: AggregatingMcpServer,
    *,
    agent_claims: dict[str, Any],
    params: dict[str, Any],
) -> dict[str, Any]:
    client_version = params.get('protocolVersion')
    protocol_version = negotiate_protocol_version(
        str(client_version) if client_version is not None else None
    )
    agent = server._gateway.resolve_agent(agent_claims)
    urls = server._gateway.get_service_urls()
    from shellui_django.mcp.gateway import scope_service_ids

    scope = scope_service_ids(agent_claims)
    allowed_rows = set(agent.services_allowed or []) if agent else set()
    connected = sorted(sid for sid in scope if sid in allowed_rows and sid in urls)
    return {
        'protocolVersion': protocol_version,
        'capabilities': server_capabilities(),
        'serverInfo': {
            'name': MCP_SERVER_NAME,
            'title': 'Shellui AI MCP gateway',
            'version': MCP_SERVER_VERSION,
        },
        'instructions': shellui_gateway_instructions(
            title=server._gateway.instructions_title,
            connected_services=connected,
            local_service_id=server._gateway.local_service_id,
        ),
    }


def _accepts_streamable_http(accept_header: str | None) -> bool:
    if not accept_header:
        return False
    lowered = accept_header.lower()
    return 'application/json' in lowered and 'text/event-stream' in lowered


def _parse_protocol_version_header(request: HttpRequest) -> str | None:
    raw = request.headers.get('MCP-Protocol-Version') or request.headers.get('Mcp-Protocol-Version')
    if raw is None:
        return None
    return str(raw).strip() or None


def _validate_protocol_version_header(request: HttpRequest, req_id: Any) -> JsonResponse | None:
    version = _parse_protocol_version_header(request)
    if version is None:
        return None
    if version not in _SUPPORTED_PROTOCOL_SET:
        return JsonResponse(
            McpServer._error(req_id, -32600, 'Unsupported MCP-Protocol-Version'),
            status=400,
        )
    return None


def _new_session_id() -> str:
    # Visible ASCII per MCP transport spec (token_urlsafe uses [A-Za-z0-9_-]).
    return secrets.token_urlsafe(32)


def _store_session(session_id: str, *, company_id: int, agent_id: str, protocol_version: str) -> None:
    cache.set(
        f'{MCP_SESSION_CACHE_PREFIX}{session_id}',
        {
            'company_id': company_id,
            'agent_id': agent_id,
            'protocol_version': protocol_version,
        },
        MCP_SESSION_TTL_SECONDS,
    )


def _session_record(session_id: str) -> dict[str, Any] | None:
    meta = cache.get(f'{MCP_SESSION_CACHE_PREFIX}{session_id}')
    return meta if isinstance(meta, dict) else None


def _validate_session(
    request: HttpRequest,
    *,
    company_id: int,
    agent_id: str,
    method: str | None,
    req_id: Any,
) -> HttpResponse | JsonResponse | None:
    if method == 'initialize':
        return None
    session_id = request.headers.get('Mcp-Session-Id') or request.headers.get('MCP-Session-Id')
    if not session_id:
        return None
    record = _session_record(str(session_id))
    if record is None:
        return JsonResponse({'error': 'session_not_found'}, status=404)
    try:
        if int(record.get('company_id')) != int(company_id):
            return JsonResponse({'error': 'session_forbidden'}, status=403)
    except (TypeError, ValueError):
        return JsonResponse({'error': 'session_forbidden'}, status=403)
    if str(record.get('agent_id') or '') != agent_id:
        return JsonResponse({'error': 'session_forbidden'}, status=403)
    header_version = _parse_protocol_version_header(request)
    if header_version is not None and header_version != str(record.get('protocol_version') or ''):
        return JsonResponse(
            McpServer._error(req_id, -32600, 'MCP-Protocol-Version mismatch'),
            status=400,
        )
    return None


def paginate_tools(tools: list[dict[str, Any]], params: dict[str, Any]) -> dict[str, Any]:
    cursor = params.get('cursor')
    start = 0
    if cursor is not None and str(cursor).strip():
        try:
            start = int(base64.urlsafe_b64decode(str(cursor).encode()).decode())
        except (ValueError, OSError):
            start = 0
    end = start + MCP_TOOLS_PAGE_SIZE
    page = tools[start:end]
    result: dict[str, Any] = {'tools': page}
    if end < len(tools):
        result['nextCursor'] = base64.urlsafe_b64encode(str(end).encode()).decode()
    return result


def _is_jsonrpc_notification(payload: dict[str, Any]) -> bool:
    return 'method' in payload and 'id' not in payload


def _gateway_precheck(
    server: AggregatingMcpServer,
    request: HttpRequest,
    *,
    agent_claims: dict[str, Any] | None,
) -> JsonResponse | None:
    if request.method != 'POST':
        return JsonResponse({'error': 'method_not_allowed'}, status=405)
    if agent_claims is None:
        return JsonResponse({'error': 'unauthorized'}, status=401)
    agent_id = str(agent_claims.get('agent_id') or '')
    if not agent_id:
        return JsonResponse({'error': 'unauthorized'}, status=401)
    if check_agent_rate_limit(agent_id):
        return JsonResponse({'error': 'rate_limited'}, status=429)
    company_id = agent_claims.get('company_id')
    try:
        company_id_int = int(company_id) if company_id is not None else None
    except (TypeError, ValueError):
        company_id_int = None
    if server.identity_revocation_check and server.identity_revocation_check(agent_id, company_id_int):
        return JsonResponse({'error': 'agent_revoked'}, status=403)
    if not McpServer._service_allowed(agent_claims, server.service_name):
        return JsonResponse({'error': 'forbidden'}, status=403)
    return None


def handle_mcp_gateway_request(
    server: AggregatingMcpServer,
    request: HttpRequest,
    *,
    agent_claims: dict[str, Any] | None,
) -> HttpResponse | JsonResponse:
    blocked = _gateway_precheck(server, request, agent_claims=agent_claims)
    if blocked is not None:
        return blocked
    assert agent_claims is not None

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'invalid_json'}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({'error': 'invalid_json'}, status=400)

    req_id = payload.get('id')

    if not _accepts_streamable_http(request.headers.get('Accept')):
        return JsonResponse(
            McpServer._error(
                req_id,
                -32600,
                'Accept must include application/json and text/event-stream',
            ),
            status=400,
        )

    method = payload.get('method')
    params = payload.get('params') or {}
    if not isinstance(params, dict):
        params = {}

    company_id = int(agent_claims['company_id'])
    agent_id = str(agent_claims['agent_id'])

    protocol_error = _validate_protocol_version_header(request, req_id)
    if protocol_error is not None and method != 'initialize':
        return protocol_error

    session_error = _validate_session(
        request,
        company_id=company_id,
        agent_id=agent_id,
        method=str(method) if method is not None else None,
        req_id=req_id,
    )
    if session_error is not None:
        return session_error

    if _is_jsonrpc_notification(payload):
        if method == 'notifications/initialized':
            return HttpResponse(status=202)
        return HttpResponse(status=202)

    if method == 'initialize':
        result = build_initialize_result(server, agent_claims=agent_claims, params=params)
        session_id = _new_session_id()
        _store_session(
            session_id,
            company_id=company_id,
            agent_id=agent_id,
            protocol_version=str(result['protocolVersion']),
        )
        response = JsonResponse(McpServer._result(req_id, result))
        response['Mcp-Session-Id'] = session_id
        response['Content-Type'] = 'application/json'
        return response

    if method == 'tools/list':
        return server._aggregated_tools_list(req_id, agent_claims, params)

    if method == 'tools/call':
        timer = begin_mcp_tool_call_timer()
        try:
            forwarded = server._maybe_forward_tool_call(request, req_id, params, agent_claims)
            if forwarded is not None:
                return forwarded
            return server._tools_call(request, req_id, params, agent_claims)
        finally:
            reset_mcp_tool_call_timer(timer)

    return JsonResponse(McpServer._error(req_id, -32601, 'Method not found'))
