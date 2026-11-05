"""Aggregated MCP gateway at ai-service ``POST /c/<company_id>/mcp``."""

from __future__ import annotations

import contextvars
import json

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from shellui_django.mcp.gateway import (
    AggregatingMcpServer,
    McpGatewayConfig,
    public_mcp_tools,
    scope_service_ids,
    service_allowed,
)
from apps.connector.mcp_tool_naming import gateway_export_name, service_local_tool_name
from apps.connector.mcp_openapi_tools import tools_from_schema
from apps.connector.mcp_tool_schema import normalize_mcp_tool

from apps.authapi.agent_tokens import authenticate_agent_bearer
from apps.connector.mcp_protocol import handle_mcp_gateway_request, paginate_tools
from apps.connector.agent_record import AgentRecord
from apps.connector.downstream_tokens import DownstreamTokenError, mint_downstream_access_token
from apps.connector.mcp_call_log import client_ip_from_request, mcp_call_result
from apps.connector.mcp_identity import agent_is_revoked, forward_call_log, identity_revocation_unavailable
from apps.connector.mcp_urls import (
    PLAIN_MCP_MESSAGE,
    company_audience_matches,
    company_mcp_resource,
    company_metadata_url,
)
from apps.connector.services import configured_service_urls, downstream_resource_for

_TOOLS_LIST_CACHE_PREFIX = 'mcp_gateway:tools:'

_server: AggregatingMcpServer | None = None
_mcp_http_request: contextvars.ContextVar[HttpRequest | None] = contextvars.ContextVar(
    'mcp_http_request', default=None
)


def _record_mcp_call(entry: dict) -> None:
    request = _mcp_http_request.get()
    entry['client_ip'] = client_ip_from_request(request)
    status_code = int(entry.get('status') or 0)
    is_error = entry.pop('is_error', None)
    entry['result'] = mcp_call_result(status_code=status_code, is_error=is_error)
    entry.pop('arguments', None)
    forward_call_log(entry)


def iter_gateway_remote_exports(
    tools: list[dict],
    *,
    service_id: str,
) -> list[tuple[str, dict, dict[str, str]]]:
    """Build gateway export names and downstream routes for one remote ``tools/list``."""
    taken: set[str] = set()
    rows: list[tuple[str, dict, dict[str, str]]] = []
    for tool in tools:
        downstream_name = str(tool.get('name') or '')
        if not downstream_name:
            continue
        canonical = service_local_tool_name(tool, service_id=service_id)
        export_name = gateway_export_name(service_id, canonical, taken=taken)
        route = {'service_id': service_id, 'downstream_name': downstream_name}
        rows.append((export_name, {**tool, 'name': export_name}, route))
    return rows


def prefixed_tool_catalog(
    local_tools: list[dict],
    remote_by_service: dict[str, list[dict]],
    *,
    local_service_id: str = 'ai',
    remember_route=None,
) -> list[dict]:
    """Every exported tool is ``<service>_<verb>_<noun>`` (single underscore, no ``api_v1``)."""
    merged: list[dict] = []
    taken: set[str] = set()
    for tool in local_tools:
        name = str(tool.get('name') or '')
        if not name:
            continue
        export_name = gateway_export_name(local_service_id, name, taken=taken)
        taken.add(export_name)
        merged.append({**tool, 'name': export_name})
    for service_id, tools in remote_by_service.items():
        for export_name, exported, route in iter_gateway_remote_exports(tools, service_id=service_id):
            if remember_route is not None:
                remember_route(export_name, route['service_id'], route['downstream_name'])
            merged.append(exported)
    return merged


class PrefixingMcpServer(AggregatingMcpServer):
    """Same gateway, with an unambiguous service prefix on every downstream tool."""

    def _service_id_from_export_name(self, export_name: str) -> str | None:
        service_id, sep, rest = str(export_name or '').partition('_')
        if not sep or not service_id or not rest:
            return None
        if service_id == self._gateway.local_service_id:
            return None
        if service_id not in self._gateway.get_service_urls():
            return None
        return service_id

    def _route_from_cached_tools_list(self, export_name: str) -> dict[str, str] | None:
        service_id = self._service_id_from_export_name(export_name)
        if service_id is None:
            return None
        mcp_url = self._gateway.get_service_urls()[service_id]
        tools = self._cache().get(f'{_TOOLS_LIST_CACHE_PREFIX}{mcp_url}')
        if not isinstance(tools, list):
            return None
        for name, _tool, route in iter_gateway_remote_exports(tools, service_id=service_id):
            if name == export_name:
                return route
        return None

    def _remember_routes_for_service_tools(self, service_id: str, tools: list[dict]) -> None:
        for export_name, _tool, route in iter_gateway_remote_exports(tools, service_id=service_id):
            self._remember_route(export_name, route['service_id'], route['downstream_name'])

    def _ensure_routes_for_export(self, export_name: str, agent_claims: dict) -> None:
        if self._lookup_route(export_name) is not None:
            return
        service_id = self._service_id_from_export_name(export_name)
        if service_id is None:
            return
        agent = self._gateway.resolve_agent(agent_claims)
        if agent is None:
            return
        scope = scope_service_ids(agent_claims)
        if not service_allowed(list(scope), service_id):
            return
        if not service_allowed(agent.services_allowed or [], service_id):
            return
        mcp_url = self._gateway.get_service_urls().get(service_id)
        if not mcp_url:
            return
        token = self._gateway.mint_downstream_token(agent, mcp_url)
        tools = self._fetch_remote_tools_list(mcp_url=mcp_url, bearer_token=token)
        if isinstance(tools, list):
            self._remember_routes_for_service_tools(service_id, tools)

    def _lookup_route(self, tool_name: str) -> dict[str, str] | None:
        cached = super()._lookup_route(tool_name)
        if cached is not None:
            return cached
        route = self._route_from_cached_tools_list(tool_name)
        if route is not None:
            self._remember_route(tool_name, route['service_id'], route['downstream_name'])
        return route

    def _local_tool_export_name(self, export_name: str) -> str | None:
        """Map ``ai_<tool>`` back to the local OpenAPI tool name for ``tools/call``."""
        local_id = self._gateway.local_service_id
        prefix = f'{local_id}_'
        raw = str(export_name or '')
        if not raw.startswith(prefix):
            return None
        downstream = raw[len(prefix) :]
        if not downstream:
            return None
        local_names = {str(t.get('name') or '') for t in tools_from_schema(self.schema_provider())}
        return downstream if downstream in local_names else None

    def handle(self, request: HttpRequest, *, agent_claims: dict | None):
        return handle_mcp_gateway_request(self, request, agent_claims=agent_claims)

    def _using_connector_tool_catalog(self, handler, request, req_id, params, agent_claims):
        import shellui_django.mcp.gateway as gw
        import shellui_django.mcp.server as srv

        orig_gw, orig_srv = gw.tools_from_schema, srv.tools_from_schema
        gw.tools_from_schema = srv.tools_from_schema = tools_from_schema
        try:
            return handler(request, req_id, params, agent_claims)
        finally:
            gw.tools_from_schema, srv.tools_from_schema = orig_gw, orig_srv

    def _maybe_forward_tool_call(self, request: HttpRequest, req_id, params, agent_claims):
        call_params = dict(params or {})
        export_name = str(call_params.get('name') or '')
        local_name = self._local_tool_export_name(export_name)
        if local_name is not None:
            call_params['name'] = local_name
            return self._tools_call(request, req_id, call_params, agent_claims)

        self._ensure_routes_for_export(export_name, agent_claims)

        response = self._using_connector_tool_catalog(
            lambda *args: super(PrefixingMcpServer, self)._maybe_forward_tool_call(*args),
            request,
            req_id,
            call_params,
            agent_claims,
        )
        if response is None or not self.on_call:
            return response
        tool_name = str(params.get('name') or '')
        route = self._lookup_route(tool_name)
        if route is None:
            return response
        is_error = False
        try:
            body = json.loads(response.content)
            result = body.get('result') if isinstance(body, dict) else None
            if isinstance(result, dict):
                is_error = bool(result.get('isError'))
        except (ValueError, TypeError, AttributeError):
            is_error = response.status_code >= 400
        self.on_call(
            {
                'agent_id': agent_claims.get('agent_id'),
                'company_id': agent_claims.get('company_id'),
                'service': route['service_id'],
                'tool': tool_name,
                'method': 'POST',
                'path': f"/mcp (forward {route['service_id']})",
                'status': response.status_code,
                'is_error': is_error,
            }
        )
        return response

    def _tools_call(self, request, req_id, params, agent_claims):
        call_params = dict(params or {})
        local_name = self._local_tool_export_name(str(call_params.get('name') or ''))
        if local_name is not None:
            call_params['name'] = local_name

        return self._using_connector_tool_catalog(
            lambda *args: super(PrefixingMcpServer, self)._tools_call(*args),
            request,
            req_id,
            call_params,
            agent_claims,
        )

    def _aggregated_tools_list(self, req_id, agent_claims, params=None):
        agent = self._gateway.resolve_agent(agent_claims)
        if agent is None:
            return JsonResponse(self._error(req_id, -32603, 'Forbidden'))
        allowed = scope_service_ids(agent_claims) & set(agent.services_allowed or [])
        local = public_mcp_tools(tools_from_schema(self.schema_provider()))
        local_id = self._gateway.local_service_id
        remote: dict[str, list[dict]] = {}
        for service_id, mcp_url in self._gateway.get_service_urls().items():
            if service_id == local_id or service_id not in allowed:
                continue
            token = self._gateway.mint_downstream_token(agent, mcp_url)
            tools = self._fetch_remote_tools_list(mcp_url=mcp_url, bearer_token=token)
            if tools is not None:
                remote[service_id] = tools
        tools = prefixed_tool_catalog(
            local,
            remote,
            local_service_id=local_id,
            remember_route=self._remember_route,
        )
        tools = [normalize_mcp_tool(tool) for tool in tools]
        page = paginate_tools(tools, params or {})
        return JsonResponse(self._result(req_id, page))


def _schema() -> dict:
    generator = SchemaGenerator()
    return generator.get_schema(request=None, public=True)


def _mint_token(agent: AgentRecord, mcp_url: str) -> str:
    # The gateway passes the URL it calls, which may be internal. Identity binds tokens to the
    # public resource the downstream service expects, so map it and refuse unknown URLs.
    resource = downstream_resource_for(mcp_url)
    if not resource:
        raise DownstreamTokenError('MCP service is not configured.')
    return mint_downstream_access_token(agent, resource=resource)


def _get_server() -> AggregatingMcpServer:
    global _server
    if _server is None:
        gateway = McpGatewayConfig(
            get_service_urls=configured_service_urls,
            resolve_agent=lambda claims: AgentRecord.from_claims(claims),
            mint_downstream_token=lambda agent, resource: _mint_token(agent, resource),
            local_service_id='ai',
            tools_cache_ttl_seconds=int(getattr(settings, 'MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS', 30)),
            downstream_timeout_seconds=float(getattr(settings, 'MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 5)),
            instructions_title='Shellui AI MCP gateway',
        )
        _server = PrefixingMcpServer(
            gateway=gateway,
            schema_provider=_schema,
            urlconf=settings.ROOT_URLCONF,
            service_name='ai',
            identity_revocation_check=lambda agent_id, company_id: agent_is_revoked(agent_id, company_id),
            on_call=_record_mcp_call,
        )
    return _server


def _agent_claims(request: HttpRequest, company_id: int) -> dict | None:
    header = request.headers.get('Authorization', '')
    if not header.lower().startswith('bearer '):
        return None
    raw = header.split(' ', 1)[1].strip()
    expected_resource = company_mcp_resource(request, company_id)
    if not expected_resource:
        return None
    result = authenticate_agent_bearer(raw, expected_resource=expected_resource)
    if not result:
        return None
    principal, claims = result
    if not company_audience_matches(claims, expected_resource):
        return None
    # The URL names the tenant. A token for another company never works here, even with a matching aud.
    try:
        if int(claims.get('company_id')) != int(company_id):
            return None
    except (TypeError, ValueError):
        return None
    request.user = principal
    drf_request = Request(request)
    drf_request.user = principal
    return dict(claims)


def _unauthorized(request: HttpRequest, company_id: int) -> JsonResponse:
    response = JsonResponse({'error': 'unauthorized'}, status=401)
    response['WWW-Authenticate'] = f'Bearer resource_metadata="{company_metadata_url(request, company_id)}"'
    return response


@csrf_exempt
def mcp_endpoint(request: HttpRequest, company_id: int):
    if int(company_id) < 1:
        return JsonResponse({'error': 'not_found'}, status=404)
    if request.method == 'GET':
        return JsonResponse({'error': 'method_not_allowed'}, status=405)
    claims = _agent_claims(request, company_id)
    if claims is None and request.method == 'POST':
        return _unauthorized(request, company_id)
    if claims is not None and identity_revocation_unavailable():
        return JsonResponse({'error': 'identity_unavailable'}, status=503)
    token = _mcp_http_request.set(request)
    try:
        return _get_server().handle(request, agent_claims=claims)
    except DownstreamTokenError:
        return JsonResponse({'error': 'downstream_token_unavailable'}, status=503)
    finally:
        _mcp_http_request.reset(token)


@csrf_exempt
def mcp_plain_endpoint(request: HttpRequest):
    """``/mcp`` has no company, so it never authenticates or picks a default tenant."""
    return JsonResponse({'error': 'company_required', 'message': PLAIN_MCP_MESSAGE}, status=404)
