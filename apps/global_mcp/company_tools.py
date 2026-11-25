"""Company tools: list, wait, and forward discovery calls to the regional gateway."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import requests

from apps.global_mcp.approvals import approval_url
from apps.global_mcp.exchange import ExchangeError, regional_access_token
from apps.global_mcp.grants import (
    active_grant,
    is_narrowing,
    is_widening,
    maybe_setup_grant,
    narrow_grant,
    normalize_grant_request,
    revoke_grant,
)
from apps.global_mcp.models import GlobalAgent, GlobalMcpApprovalRequest
from apps.global_mcp.saas_client import SaasError, request_json
from apps.global_mcp.tokens import issue_saas_api_token
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

CORRELATION_HEADER = 'X-Shellui-Correlation-Id'


def builtin_tools() -> list[dict]:
    return [
        {
            'name': 'ai_list_companies',
            'description': 'List Shellui projects you belong to, with region, status, and whether this agent has a grant.',
            'inputSchema': {'type': 'object', 'additionalProperties': False, 'properties': {}},
            'annotations': {'readOnlyHint': True, 'destructiveHint': False},
        },
        {
            'name': 'ai_wait_for_company',
            'description': 'Wait until a Shellui project is active or failed. Bounded to about 60 seconds.',
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['company_id'],
                'properties': {'company_id': {'type': 'string'}},
            },
            'annotations': {'readOnlyHint': True, 'destructiveHint': False},
        },
        {
            'name': 'ai_company_search_tools',
            'description': 'Search tools on one project\'s regional AI gateway.',
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['company_id', 'query'],
                'properties': {
                    'company_id': {'type': 'string'},
                    'query': {'type': 'string'},
                    'limit': {'type': 'integer'},
                },
            },
            'annotations': {'readOnlyHint': True, 'destructiveHint': False},
        },
        {
            'name': 'ai_company_describe_tool',
            'description': 'Describe tools on one project\'s regional AI gateway.',
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['company_id', 'names'],
                'properties': {
                    'company_id': {'type': 'string'},
                    'names': {'type': 'array', 'items': {'type': 'string'}},
                },
            },
            'annotations': {'readOnlyHint': True, 'destructiveHint': False},
        },
        {
            'name': 'ai_call_company_tool',
            'description': 'Call one tool on a project\'s regional AI gateway. Regional approval links come back unchanged.',
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['company_id', 'tool'],
                'properties': {
                    'company_id': {'type': 'string'},
                    'tool': {'type': 'string'},
                    'arguments': {'type': 'object'},
                },
            },
            'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'openWorldHint': True},
        },
    ]


def _token(agent: GlobalAgent) -> str:
    token, _claims = issue_saas_api_token(agent)
    return token


def fetch_company(agent: GlobalAgent, company_id: str) -> dict:
    status, payload = request_json('GET', f'/api/v1/companies/{company_id}', token=_token(agent))
    if status == 404 or not isinstance(payload, dict):
        raise SaasError(status, payload, 'Project was not found.')
    if status >= 400:
        raise SaasError(status, payload, 'Project was not found.')
    return payload


def region_urls(company: dict) -> tuple[str, str, str]:
    raw_region = company.get('region')
    if isinstance(raw_region, dict):
        region = raw_region
        code = str(region.get('code') or company.get('region_code') or '')
    elif isinstance(raw_region, str) and raw_region.strip():
        region = {}
        code = raw_region.strip()
    else:
        region = {}
        code = str(company.get('region_code') or '')
    endpoints = company.get('endpoints') if isinstance(company.get('endpoints'), dict) else {}
    mcp = endpoints.get('mcp') if isinstance(endpoints.get('mcp'), dict) else {}
    ai_url = str(region.get('ai_url') or company.get('ai_url') or mcp.get('ai') or '').rstrip('/')
    identity_url = str(region.get('identity_url') or company.get('identity_url') or mcp.get('identity') or '').rstrip('/')
    return ai_url, identity_url, code


def caller_is_owner(company: dict) -> bool:
    role = str(company.get('role') or company.get('caller_role') or '').lower()
    return role in {'owner', 'ROLE_OWNER'}


def caller_is_member(company: dict) -> bool:
    if caller_is_owner(company):
        return True
    role = str(company.get('role') or company.get('caller_role') or '').lower()
    return role in {'staff', 'member', 'admin'} or bool(company.get('is_member'))


def company_rows(payload) -> list:
    """Accept the saas-service array body, or a dict wrapper with results or companies."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if isinstance(payload.get('results'), list):
            return payload['results']
        if isinstance(payload.get('companies'), list):
            return payload['companies']
    return []


def list_companies(agent: GlobalAgent) -> dict:
    status, payload = request_json('GET', '/api/v1/companies', token=_token(agent))
    if status >= 400:
        raise SaasError(status, payload, 'Could not list projects.')
    if payload is not None and not isinstance(payload, (list, dict)):
        raise SaasError(status, payload, 'Could not list projects.')
    rows = company_rows(payload)
    listed = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        company_id = str(row.get('id') or '')
        grant = active_grant(agent, company_id) if company_id else None
        ai_url, _identity, code = region_urls(row)
        listed.append(
            {
                'id': company_id,
                'name': row.get('name'),
                'status': row.get('status'),
                'region': code,
                'ai_url': ai_url,
                'regional_company_id': row.get('regional_company_id'),
                'delegation': None
                if grant is None
                else {
                    'binding_version': grant.binding_version,
                    'services': grant.services,
                    'max_access_mode': grant.max_access_mode,
                    'max_read_level': grant.max_read_level,
                    'max_destructive': grant.max_destructive,
                },
            }
        )
    return {'companies': listed}


def wait_for_company(agent: GlobalAgent, company_id: str, *, sleep=time.sleep) -> dict:
    deadline = time.monotonic() + float(settings.GLOBAL_COMPANY_WAIT_SECONDS)
    interval = float(settings.GLOBAL_COMPANY_POLL_SECONDS)
    last = fetch_company(agent, company_id)
    while str(last.get('status') or '') not in {'active', 'failed'}:
        if time.monotonic() >= deadline:
            return {'status': last.get('status'), 'company': last, 'timed_out': True}
        sleep(interval)
        last = fetch_company(agent, company_id)
    return {'status': last.get('status'), 'company': last, 'timed_out': False}


def _grant_link(agent: GlobalAgent, company: dict, arguments: dict) -> dict:
    row = GlobalMcpApprovalRequest.objects.create(
        agent=agent,
        owner_sub=agent.owner_sub,
        kind=GlobalMcpApprovalRequest.KIND_GRANT,
        service='ai',
        action='ai_grant_company_access',
        arguments_hash='grant',
        arguments={**arguments, 'company': company},
        arguments_redacted={'company_id': str(company.get('id') or '')},
        is_destructive=False,
        channel='link',
        short_action_summary=f"Grant this agent access to {company.get('name') or 'the project'}.",
        global_company_id=company.get('id'),
        status=GlobalMcpApprovalRequest.STATUS_PENDING,
        expires_at=timezone.now() + timedelta(minutes=15),
    )
    return {
        'approval_required': True,
        'approval_url': approval_url(row.id),
        'approval_id': str(row.id),
        'message': 'This agent needs a grant for that project. Open the link to approve it.',
    }


def ensure_grant(agent: GlobalAgent, company: dict) -> tuple[Any, dict | None]:
    grant = active_grant(agent, str(company.get('id') or ''))
    if grant is not None:
        return grant, None
    if not caller_is_owner(company):
        return None, {'error': 'Only an owner can grant this agent access to the project.'}
    return None, _grant_link(agent, company, {'company_id': str(company.get('id') or '')})


def forward_company_tool(
    agent: GlobalAgent,
    company: dict,
    tool: str,
    arguments: dict,
    *,
    correlation_id: str,
) -> dict:
    grant, missing = ensure_grant(agent, company)
    if missing is not None:
        return missing
    if not caller_is_member(company):
        return {'error': 'You are not a member of this project.'}
    ai_url, identity_url, _code = region_urls(company)
    regional_id = str(company.get('regional_company_id') or '').strip()
    if not ai_url or not identity_url or not regional_id.isdigit():
        return {'error': 'This project does not have a regional AI URL yet.'}
    resource = f'{ai_url}/c/{int(regional_id)}/mcp'
    setup = None
    if (
        agent.setup_flow
        and agent.setup_company_id
        and str(agent.setup_company_id) == str(company.get('id') or '')
        and agent.setup_expires_at
        and timezone.now() < agent.setup_expires_at
    ):
        remaining = int((agent.setup_expires_at - timezone.now()).total_seconds())
        ttl = max(600, min(int(getattr(settings, 'MCP_SETUP_APPROVAL_SESSION_TTL_SECONDS', 900)), 900, remaining))
        if remaining >= 600:
            setup = {
                'active': True,
                'regional_company_id': int(regional_id),
                'setup_expires_at': min(int(agent.setup_expires_at.timestamp()), int(time.time()) + 90),
                'mcp_session_ttl_seconds': ttl,
            }
    try:
        access = regional_access_token(
            agent,
            company,
            identity_url=identity_url,
            resource=resource,
            services=list(grant.services or []),
            binding_version=int(grant.binding_version),
            access_mode=grant.max_access_mode,
            read_level=grant.max_read_level,
            destructive=bool(grant.max_destructive),
            setup=setup,
        )
    except ExchangeError as exc:
        return {'error': exc.description or 'Region identity refused the exchange.'}
    return call_regional(
        resource,
        access,
        tool,
        arguments,
        correlation_id=correlation_id,
    )


def call_regional(url: str, token: str, tool: str, arguments: dict, *, correlation_id: str) -> dict:
    response = requests.post(
        url,
        json={
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': tool, 'arguments': arguments or {}},
        },
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json, text/event-stream',
            'Content-Type': 'application/json',
            CORRELATION_HEADER: correlation_id,
            'MCP-Protocol-Version': '2025-06-18',
        },
        timeout=float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 15) or 15),
    )
    content_type = (response.headers.get('Content-Type') or '').lower()
    if 'text/event-stream' in content_type:
        relay = parse_sse_relay(response.text)
        return {
            'relay': relay,
            'status': response.status_code,
            '_relay_call': {
                'url': url,
                'token': token,
                'session_id': response.headers.get('Mcp-Session-Id') or '',
                'correlation_id': correlation_id,
            },
        }
    try:
        payload = response.json()
    except ValueError:
        return {'error': 'The regional gateway did not return JSON.', 'status': response.status_code}
    result = payload.get('result') if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        result = payload if isinstance(payload, dict) else {'error': 'Empty regional response.'}
    return {'result': result, 'status': response.status_code}


def relay_elicitation_answer(relay_call: dict, result: dict | None) -> dict:
    """Post the client's elicitation answer back to the regional gateway."""
    if not isinstance(relay_call, dict) or not relay_call.get('url') or not relay_call.get('token'):
        return {'error': 'The regional approval session is gone.'}
    answer = result if isinstance(result, dict) else {}
    rpc = answer if answer.get('jsonrpc') else {
        'jsonrpc': '2.0',
        'id': answer.get('id') or 'elicit',
        'result': answer.get('result', answer),
    }
    headers = {
        'Authorization': f"Bearer {relay_call['token']}",
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        CORRELATION_HEADER: str(relay_call.get('correlation_id') or ''),
    }
    session_id = str(relay_call.get('session_id') or '')
    if session_id:
        headers['Mcp-Session-Id'] = session_id
    response = requests.post(
        str(relay_call['url']),
        json=rpc,
        headers=headers,
        timeout=float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 15) or 15),
    )
    try:
        payload = response.json()
    except ValueError:
        payload = parse_sse_relay(response.text).get('result') or {'error': 'The regional gateway did not return JSON.'}
    if isinstance(payload, dict) and isinstance(payload.get('result'), dict):
        return payload['result']
    return payload if isinstance(payload, dict) else {'error': 'Empty regional response.'}


def parse_sse_relay(body: str) -> dict:
    """Pull the elicitation and the final tools/call result out of a regional SSE body."""
    events = []
    for block in body.split('\n\n'):
        data = '\n'.join(line[5:].strip() for line in block.splitlines() if line.startswith('data:'))
        if not data:
            continue
        try:
            events.append(json.loads(data))
        except json.JSONDecodeError:
            continue
    elicitation = None
    final = None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get('method') == 'elicitation/create':
            elicitation = event.get('params') if isinstance(event.get('params'), dict) else {}
        if 'result' in event:
            final = event.get('result')
    relay = {'events': events}
    if isinstance(elicitation, dict):
        mode = str(elicitation.get('mode') or 'form')
        if mode == 'url' or elicitation.get('url'):
            relay['approval_url'] = str(elicitation.get('url') or '')
            relay['elicitation'] = {'mode': 'url', 'url': relay['approval_url'], 'message': elicitation.get('message')}
        else:
            relay['elicitation'] = elicitation
    if isinstance(final, dict):
        relay['result'] = final
        url = _approval_url_from_result(final)
        if url:
            relay['approval_url'] = url
    return relay


def _approval_url_from_result(result: dict) -> str:
    if isinstance(result.get('approval_url'), str):
        return result['approval_url']
    structured = result.get('structuredContent')
    if isinstance(structured, dict) and isinstance(structured.get('approval_url'), str):
        return structured['approval_url']
    return ''


def handle_builtin(agent: GlobalAgent, name: str, arguments: dict, *, correlation_id: str) -> dict:
    arguments = arguments if isinstance(arguments, dict) else {}
    if name == 'ai_list_companies':
        return list_companies(agent)
    if name == 'ai_wait_for_company':
        return wait_for_company(agent, str(arguments.get('company_id') or ''))
    if name in {'ai_company_search_tools', 'ai_company_describe_tool', 'ai_call_company_tool'}:
        company = fetch_company(agent, str(arguments.get('company_id') or ''))
        if name == 'ai_company_search_tools':
            forwarded = forward_company_tool(
                agent,
                company,
                'ai_search_tools',
                {'query': arguments.get('query'), 'limit': arguments.get('limit') or 8},
                correlation_id=correlation_id,
            )
        elif name == 'ai_company_describe_tool':
            forwarded = forward_company_tool(
                agent,
                company,
                'ai_describe_tool',
                {'names': arguments.get('names') or []},
                correlation_id=correlation_id,
            )
        else:
            forwarded = forward_company_tool(
                agent,
                company,
                str(arguments.get('tool') or ''),
                arguments.get('arguments') if isinstance(arguments.get('arguments'), dict) else {},
                correlation_id=correlation_id,
            )
        forwarded['global_company_id'] = str(company.get('id') or '')
        forwarded['regional_company_id'] = str(company.get('regional_company_id') or '')
        _ai, _identity, code = region_urls(company)
        forwarded['region'] = code
        return forwarded
    if name == 'ai_grant_company_access':
        return grant_company(agent, arguments)
    if name == 'ai_revoke_company_access':
        return revoke_company(agent, str(arguments.get('company_id') or ''))
    raise KeyError(name)


def grant_company(agent: GlobalAgent, arguments: dict) -> dict:
    company = fetch_company(agent, str(arguments.get('company_id') or ''))
    if not caller_is_owner(company):
        return {'error': 'Only an owner can grant this agent access to the project.'}
    requested = normalize_grant_request(arguments, agent)
    existing = active_grant(agent, str(company.get('id') or ''))
    if existing is not None and is_narrowing(existing, requested) and not is_widening(existing, requested):
        updated = narrow_grant(existing, requested)
        return {'binding_version': updated.binding_version, 'services': updated.services, 'narrowed': True}
    if existing is not None and not is_widening(existing, requested) and not is_narrowing(existing, requested):
        return {'binding_version': existing.binding_version, 'services': existing.services, 'unchanged': True}
    return _grant_link(agent, company, {**arguments, 'services': requested.services})


def revoke_company(agent: GlobalAgent, company_id: str) -> dict:
    company = fetch_company(agent, company_id)
    if not caller_is_owner(company):
        return {'error': 'Only an owner can revoke this agent.'}
    grant = active_grant(agent, str(company.get('id') or ''))
    if grant is None:
        return {'revoked': False}
    revoke_grant(grant)
    return {'revoked': True, 'binding_version': grant.binding_version}


def note_company_created(agent: GlobalAgent, payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    company_id = payload.get('id')
    if not company_id:
        return
    try:
        uuid.UUID(str(company_id))
    except ValueError:
        return
    maybe_setup_grant(agent, payload)
