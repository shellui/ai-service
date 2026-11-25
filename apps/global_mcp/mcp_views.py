"""Global MCP endpoint at /mcp. No company in the path."""

from __future__ import annotations

import json
import time
import uuid

import jwt
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from config.telemetry import annotate_mcp_span

from apps.connector.mcp_discovery import (
    describe_payload,
    discovery_tool_definitions,
    listed_tools,
    search_payload,
)
from apps.connector.mcp_form_elicitation import (
    classic_form_params,
    classic_url_params,
    elicitation_wait_seconds,
    form_elicitation_response,
    link_approval_stream,
    request_accepts_sse,
)
from apps.connector.mcp_urls import _COMPANY_PATH
from apps.global_mcp.approvals import (
    apply_form_decision,
    approval_state,
    approval_url,
    consume_approved,
    decide,
    mark_executed,
)
from apps.global_mcp.call_log import write_global_call
from apps.global_mcp.company_tools import handle_builtin, note_company_created
from apps.global_mcp.copy import REGION_ONLY_MESSAGE
from apps.global_mcp.grants import builtin_tools as grant_tools
from apps.global_mcp.models import GlobalAgent, GlobalMcpApprovalRequest
from apps.global_mcp.openapi_tools import call_saas_tool, find_tool, load_saas_tools, public_tool
from apps.global_mcp.resources import issuer, mcp_resource
from apps.global_mcp.signing import decode_rs256
from apps.global_mcp.tokens import TOKEN_MCP_ACCESS
from urllib.parse import urlsplit

_BUILTIN = {tool['name'] for tool in discovery_tool_definitions()}


def _catalog() -> list[dict]:
    from apps.global_mcp.company_tools import builtin_tools

    saas = [public_tool(tool) for tool in load_saas_tools()]
    # Keep private meta on a parallel list for execution.
    return discovery_tool_definitions() + builtin_tools() + grant_tools() + saas


def _execution_catalog() -> list[dict]:
    from apps.global_mcp.company_tools import builtin_tools

    return discovery_tool_definitions() + builtin_tools() + grant_tools() + load_saas_tools()


def _www(request: HttpRequest, *, description: str = '') -> str:
    metadata = f'{issuer() or request.build_absolute_uri("/").rstrip("/")}/.well-known/oauth-protected-resource'
    parts = ['Bearer realm="shellui"', f'resource_metadata="{metadata}"', 'scope="mcp"']
    if description:
        parts.append('error="invalid_token"')
        parts.append(f'error_description="{description}"')
    return ', '.join(parts)


def _unauthorized(request: HttpRequest, description: str, *, token_sent: bool = True) -> JsonResponse:
    response = JsonResponse(
        {'error': 'invalid_token', 'error_description': description},
        status=401,
    )
    # RFC 6750 section 3.1: no error code in the challenge when no token was sent.
    response['WWW-Authenticate'] = _www(request, description=description if token_sent else '')
    return response


def _looks_regional(token: str) -> bool:
    try:
        claims = jwt.decode(token, options={'verify_signature': False})
    except jwt.PyJWTError:
        return False
    if not isinstance(claims, dict):
        return False
    aud = claims.get('aud')
    if isinstance(aud, list):
        aud = aud[0] if aud else ''
    path = urlsplit(str(aud or '')).path.rstrip('/')
    if _COMPANY_PATH.match(path):
        return True
    if claims.get('company_id') and str(claims.get('iss') or '') != issuer():
        return True
    return False


def authenticate(request: HttpRequest) -> tuple[GlobalAgent, dict] | JsonResponse:
    header = request.headers.get('Authorization', '')
    if not header.lower().startswith('bearer '):
        return _unauthorized(request, 'Bearer token required.', token_sent=False)
    raw = header.split(' ', 1)[1].strip()
    try:
        claims = decode_rs256(raw, audience=mcp_resource(request), issuer=issuer() or None)
    except jwt.PyJWTError:
        if _looks_regional(raw):
            return _unauthorized(request, REGION_ONLY_MESSAGE)
        return _unauthorized(request, 'The access token is not valid.')
    if claims.get('token_type') != TOKEN_MCP_ACCESS:
        return _unauthorized(request, 'The access token is not valid.')
    agent = GlobalAgent.objects.filter(pk=str(claims.get('agent_id') or '')).first()
    if agent is None or not agent.is_active or agent.owner_sub != str(claims.get('sub') or ''):
        return _unauthorized(request, 'The access token is not valid.')
    return agent, claims


def _rpc_result(req_id, result: dict) -> dict:
    return {'jsonrpc': '2.0', 'id': req_id, 'result': result}


def _tool_text(payload) -> dict:
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    return {'content': [{'type': 'text', 'text': text}], 'isError': False}


def _tool_error(text: str) -> dict:
    return {'content': [{'type': 'text', 'text': text}], 'isError': True}


@csrf_exempt
def global_mcp_endpoint(request: HttpRequest):
    # Every method without a valid token gets 401 and the challenge, like regional.
    # Clients such as Hermes probe with GET and read WWW-Authenticate first.
    authed = authenticate(request)
    if isinstance(authed, JsonResponse):
        return authed
    if request.method == 'DELETE':
        return HttpResponse(status=204)
    if request.method != 'POST':
        response = JsonResponse({'error': 'method_not_allowed'}, status=405)
        response['Allow'] = 'POST, DELETE'
        return response
    agent, claims = authed
    try:
        body = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}})
    if isinstance(body, list):
        return JsonResponse({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Batch is not supported'}})
    method = str(body.get('method') or '')
    req_id = body.get('id')
    params = body.get('params') if isinstance(body.get('params'), dict) else {}
    raw_tool = params.get('name') if method == 'tools/call' else ''
    annotate_mcp_span(
        method=method,
        tool_name=raw_tool if isinstance(raw_tool, str) else '',
        user_id=agent.owner_sub,
        agent_id=str(agent.id),
    )
    if req_id is None and method.startswith('notifications/'):
        return HttpResponse(status=202)
    if method == 'initialize':
        return JsonResponse(
            _rpc_result(
                req_id,
                {
                    'protocolVersion': str(params.get('protocolVersion') or '2025-06-18'),
                    'capabilities': {'tools': {'listChanged': False}},
                    'serverInfo': {'name': 'shellui-ai-global', 'version': settings.VERSION},
                },
            )
        )
    if method == 'ping':
        return JsonResponse(_rpc_result(req_id, {}))
    if method == 'tools/list':
        mode = 'all' if str(params.get('mode') or getattr(settings, 'MCP_TOOLS_LIST_MODE', 'discovery')) == 'all' else 'discovery'
        catalog = _catalog()
        if mode == 'all':
            visible = catalog
        else:
            names = {tool['name'] for tool in discovery_tool_definitions()}
            from apps.global_mcp.company_tools import builtin_tools

            names.update(tool['name'] for tool in builtin_tools())
            names.update(tool['name'] for tool in grant_tools())
            visible = [tool for tool in catalog if tool['name'] in names]
            # listed_tools also filters the discovery set. Keep our extra builtins.
            _ = listed_tools
        return JsonResponse(_rpc_result(req_id, {'tools': [public_tool(tool) if '_meta' in tool else tool for tool in visible]}))
    if method == 'tools/call':
        return _tools_call(request, agent, claims, req_id, params)
    return JsonResponse(
        {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32601, 'message': 'Method not found'}},
        status=200,
    )


def _tools_call(request, agent: GlobalAgent, claims: dict, req_id, params: dict):
    name = str(params.get('name') or '')
    arguments = params.get('arguments') if isinstance(params.get('arguments'), dict) else {}
    started = time.monotonic()
    correlation = uuid.uuid4()
    catalog = _execution_catalog()
    if name in {'ai_search_tools', 'ai_describe_tool'}:
        result = _discovery(name, arguments, catalog, agent)
        _log(agent, name, arguments, 'allowed', correlation, started)
        return JsonResponse(_rpc_result(req_id, result))
    if name == 'ai_call_tool':
        name = str(arguments.get('name') or arguments.get('tool') or '')
        arguments = arguments.get('arguments') if isinstance(arguments.get('arguments'), dict) else {}
    builtin_names = {
        'ai_list_companies',
        'ai_wait_for_company',
        'ai_company_search_tools',
        'ai_company_describe_tool',
        'ai_call_company_tool',
        'ai_grant_company_access',
        'ai_revoke_company_access',
    }
    if name in builtin_names:
        return _builtin(request, agent, name, arguments, req_id, correlation, started)
    tool = find_tool(catalog, name)
    if tool is None or '_meta' not in tool:
        _log(agent, name, arguments, 'failed', correlation, started, error_code='unknown_tool')
        return JsonResponse(_rpc_result(req_id, _tool_error('This tool was not found. Call ai_search_tools.')))
    if name == 'saas_create_companies' and agent.setup_company_id:
        _log(agent, name, arguments, 'denied', correlation, started, error_code='setup_used')
        return JsonResponse(_rpc_result(req_id, _tool_error('This agent already created a project.')))
    connection = str(request.headers.get('Mcp-Session-Id') or agent.id)
    approved = consume_approved(agent, tool, arguments)
    decision = decide(agent, tool, arguments, connection_id=connection)
    if approved is not None or decision.allowed:
        return _execute_saas(
            agent,
            tool,
            arguments,
            req_id,
            correlation,
            started,
            approval=approved,
            connection_id=connection,
        )
    if decision.error and decision.approval is None:
        _log(agent, name, arguments, 'denied', correlation, started, error_message=decision.error)
        return JsonResponse(_rpc_result(req_id, _tool_error(decision.error)))
    approval = decision.approval
    if approval is None:
        _log(agent, name, arguments, 'denied', correlation, started)
        return JsonResponse(_rpc_result(req_id, _tool_error('Approval is required.')))
    return _approval_response(
        request,
        agent,
        tool,
        arguments,
        approval,
        req_id,
        correlation,
        started,
        connection,
    )


def _discovery(name: str, arguments: dict, catalog: list[dict], agent: GlobalAgent) -> dict:
    operational = [tool for tool in catalog if tool.get('name') not in _BUILTIN]
    if name == 'ai_search_tools':
        payload = search_payload(operational, arguments, access_mode=agent.access_mode)
    else:
        payload = describe_payload(operational, arguments, access_mode=agent.access_mode)
    return _tool_text(payload)


def _execute_saas(agent, tool, arguments, req_id, correlation, started, *, approval, connection_id: str):
    from apps.global_mcp.tokens import issue_saas_api_token

    name = str(tool.get('name') or '')
    token, _claims = issue_saas_api_token(agent)
    try:
        status, payload = call_saas_tool(tool, arguments, token=token)
    except Exception as exc:
        _log(agent, name, arguments, 'error', correlation, started, error_message=str(exc))
        return JsonResponse(_rpc_result(req_id, _tool_error('The saas API could not be reached.')))
    if approval is not None:
        mark_executed(approval, connection_id=connection_id)
    if name == 'saas_create_companies' and status < 400:
        note_company_created(agent, payload)
    ok = status < 400
    _log(
        agent,
        name,
        arguments,
        'allowed' if ok else 'failed',
        correlation,
        started,
        status_code=status,
        approval_id=str(approval.id) if approval is not None else '',
        approval_channel='form' if approval is not None else 'none',
    )
    body = _tool_text(payload) if ok else _tool_error(json.dumps(payload, default=str))
    return JsonResponse(_rpc_result(req_id, body))


def _approval_response(request, agent, tool, arguments, approval, req_id, correlation, started, connection):
    name = str(tool.get('name') or '')
    url = approval_url(approval.id)
    message = approval.short_action_summary or f'Approve {name}.'
    _log(
        agent,
        name,
        arguments,
        'waiting_approval',
        correlation,
        started,
        approval_id=str(approval.id),
        approval_channel=approval.channel,
    )

    def finish(state: str | None):
        if state == 'approved':
            approval.status = GlobalMcpApprovalRequest.STATUS_APPROVED
            approval.save(update_fields=['status'])
            response = _execute_saas(
                agent, tool, arguments, req_id, correlation, started, approval=approval, connection_id=connection
            )
            try:
                return json.loads(response.content)
            except ValueError:
                return {'result': _tool_text('Approved.')}
        if state == 'denied':
            return {'result': _tool_error('Denied.')}
        return {
            'result': _tool_text(
                {'approval_required': True, 'approval_url': url, 'approval_id': str(approval.id), 'message': message}
            )
        }

    session_id = str(request.headers.get('Mcp-Session-Id') or '')
    if approval.channel == 'link' or approval.is_destructive:
        if request_accepts_sse(request):
            from django.http import StreamingHttpResponse

            stream = link_approval_stream(
                session_id=session_id,
                call_id=req_id,
                timeout_seconds=elicitation_wait_seconds(),
                approval_payload={'approval_id': str(approval.id)},
                on_page_state=finish,
                elicit_params=classic_url_params(message=message, url=url),
                approval_state=lambda payload: approval_state(str(payload.get('approval_id') or '')),
                wait_decision=_wait_local_approval,
            )
            response = StreamingHttpResponse(stream, content_type='text/event-stream')
            response['Cache-Control'] = 'no-cache'
            response['X-Accel-Buffering'] = 'no'
            if session_id:
                response['Mcp-Session-Id'] = session_id
            return response
        return JsonResponse(_rpc_result(req_id, finish(None)['result']))
    if request_accepts_sse(request):

        def on_decision(result):
            state = apply_form_decision(approval, result)
            if state == 'approved':
                return finish('approved')
            if state == 'rejected':
                return finish('denied')
            return finish(None)

        return form_elicitation_response(
            session_id=session_id,
            call_id=req_id,
            message=message,
            on_decision=on_decision,
            params=classic_form_params(message=message),
        )
    return JsonResponse(_rpc_result(req_id, finish(None)['result']))


def _wait_local_approval(approval_id, *, timeout_seconds, drain=None):
    """Poll the local approval row. Destructive links are decided on this service, not identity."""
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    while True:
        if drain is not None:
            drain()
        state = approval_state(str(approval_id or ''))
        if state in {'approved', 'denied', 'expired'}:
            return state
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.05)


def _builtin(request, agent, name, arguments, req_id, correlation, started):
    try:
        payload = handle_builtin(agent, name, arguments, correlation_id=str(correlation))
    except Exception as exc:
        _log(agent, name, arguments, 'error', correlation, started, error_message=str(exc))
        return JsonResponse(_rpc_result(req_id, _tool_error(str(exc) or 'The call failed.')))
    relay_call = payload.pop('_relay_call', None) if isinstance(payload, dict) else None
    relay = payload.get('relay') if isinstance(payload, dict) else None
    if isinstance(relay, dict) and isinstance(relay.get('elicitation'), dict):
        elicitation = relay['elicitation']
        if elicitation.get('mode') == 'url' or elicitation.get('url') or relay.get('approval_url'):
            url = str(elicitation.get('url') or relay.get('approval_url') or '')
            body = _tool_text(
                {
                    'approval_required': True,
                    'approval_url': url,
                    'message': elicitation.get('message') or 'Open the link to approve this regional action.',
                }
            )
            _log(
                agent,
                name,
                arguments,
                'waiting_approval',
                correlation,
                started,
                global_company_id=str(payload.get('global_company_id') or ''),
                regional_company_id=str(payload.get('regional_company_id') or ''),
                region=str(payload.get('region') or ''),
                approval_channel='link',
            )
            return JsonResponse(_rpc_result(req_id, body))
        if request_accepts_sse(request):

            def on_decision(result):
                from apps.global_mcp.company_tools import relay_elicitation_answer

                followed = relay_elicitation_answer(relay_call or {}, result if isinstance(result, dict) else None)
                if isinstance(followed, dict) and followed.get('error') and 'content' not in followed:
                    return {'result': _tool_error(str(followed.get('error')))}
                return {'result': _tool_text(followed)}

            return form_elicitation_response(
                session_id=str(request.headers.get('Mcp-Session-Id') or ''),
                call_id=req_id,
                message=str(elicitation.get('message') or ''),
                on_decision=on_decision,
                params=elicitation,
            )
    status_name = 'failed' if isinstance(payload, dict) and payload.get('error') else 'allowed'
    if isinstance(payload, dict) and payload.get('approval_url'):
        status_name = 'waiting_approval'
    _log(
        agent,
        name,
        arguments,
        status_name,
        correlation,
        started,
        global_company_id=str(payload.get('global_company_id') or '') if isinstance(payload, dict) else '',
        regional_company_id=str(payload.get('regional_company_id') or '') if isinstance(payload, dict) else '',
        region=str(payload.get('region') or '') if isinstance(payload, dict) else '',
        approval_channel='link' if isinstance(payload, dict) and payload.get('approval_url') else 'none',
    )
    if isinstance(payload, dict) and payload.get('error') and not payload.get('approval_url'):
        return JsonResponse(_rpc_result(req_id, _tool_error(str(payload.get('error')))))
    return JsonResponse(_rpc_result(req_id, _tool_text(payload)))


def _log(agent, name, arguments, status, correlation, started, **extra) -> None:
    write_global_call(
        agent_id=str(agent.id),
        agent_name=agent.name,
        owner_sub=agent.owner_sub,
        user_email=agent.owner_email,
        tool_name=name,
        arguments=arguments,
        status=status,
        correlation_id=correlation,
        duration_ms=int((time.monotonic() - started) * 1000),
        **extra,
    )
