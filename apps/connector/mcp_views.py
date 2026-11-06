"""Aggregated MCP gateway at ai-service ``POST /c/<company_id>/mcp``."""

from __future__ import annotations

import contextvars
import json
import logging

import requests
from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from shellui_django.mcp.gateway import (
    AggregatingMcpServer,
    McpGatewayConfig,
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
from apps.connector.mcp_approval_gate import (
    bypass_shellui_write_gate,
    enforce_tool_call_approval,
    patched_decide_write,
    reset_shellui_write_gate,
)
from apps.connector.mcp_call_audit import build_call_audit_log, legacy_result_token
from apps.connector.mcp_call_log import apply_duration_ms, client_ip_from_request, mcp_call_result
from apps.connector.mcp_identity import agent_is_revoked, forward_call_log, identity_revocation_unavailable
from apps.connector.mcp_setup_context import parse_global_company_id, parse_int_version_claim
from apps.connector.mcp_urls import (
    PLAIN_MCP_MESSAGE,
    company_audience_matches,
    company_mcp_resource,
    company_metadata_url,
)
from apps.connector.mcp_company_label import resolve_company_label
from apps.connector.mcp_tenant import apply_tenant_to_arguments, tenant_binding_from_meta
from apps.connector.mcp_tool_presentation import apply_gateway_tool_presentation
from apps.connector.services import configured_service_urls, downstream_resource_for
from shellui_django.mcp.routing import McpToolArgumentError
from shellui_django.mcp.server import McpServer

logger = logging.getLogger(__name__)

_TOOLS_LIST_CACHE_PREFIX = 'mcp_gateway:tools:'

_server: AggregatingMcpServer | None = None
_mcp_http_request: contextvars.ContextVar[HttpRequest | None] = contextvars.ContextVar(
    'mcp_http_request', default=None
)
_mcp_agent_claims: contextvars.ContextVar[dict | None] = contextvars.ContextVar('mcp_agent_claims', default=None)


def _enrich_call_log_identity_authority(entry: dict, claims: dict | None) -> None:
    """Attach ``grant_version`` and optional global binding from JWT for Identity ``mcp-call-logs``."""
    if not isinstance(claims, dict) or not claims:
        return
    gv = parse_int_version_claim(claims.get('grant_version'))
    if gv is not None:
        entry['grant_version'] = gv
    gcid = parse_global_company_id(claims.get('global_company_id'))
    cbv = parse_int_version_claim(claims.get('company_binding_version'))
    if gcid is not None and cbv is not None:
        entry['global_company_id'] = gcid
        entry['company_binding_version'] = cbv


def _record_mcp_call(entry: dict) -> None:
    apply_duration_ms(entry)
    request = _mcp_http_request.get()
    claims = _mcp_agent_claims.get() or {}
    _enrich_call_log_identity_authority(entry, claims if isinstance(claims, dict) else None)
    entry['client_ip'] = client_ip_from_request(request)
    status_code = int(entry.get('status') or 0)
    is_error = entry.pop('is_error', None)
    log_result = entry.pop('log_result', None)
    legacy = mcp_call_result(
        status_code=status_code,
        is_error=is_error,
        log_result=str(log_result) if log_result else None,
    )
    if entry.get('_mcp_audit_ready') is True:
        entry['result'] = legacy_result_token(outcome=str(entry.get('outcome') or 'failed'))
        entry.pop('_mcp_audit_ready', None)
        entry.pop('arguments', None)
        forward_call_log(entry)
        return

    server = _get_server()
    tool_name = str(entry.get('tool') or '')
    service_id = str(entry.get('service') or 'ai')
    tool_row = server._cached_export_tool(tool_name) if hasattr(server, '_cached_export_tool') else None
    method = str(entry.get('method') or 'GET')
    path = str(entry.get('path') or '')
    if tool_row and isinstance(tool_row.get('_meta'), dict):
        meta = tool_row['_meta']
        method = str(meta.get('method') or method).upper()
        if meta.get('path'):
            path = str(meta.get('path') or path)
    audit = build_call_audit_log(
        agent_claims=claims,
        service_id=service_id,
        export_name=tool_name,
        tool=tool_row,
        method=method,
        path=path,
        log_result=str(log_result) if log_result else None,
        status=status_code,
        is_error=is_error,
        approval_id=None,
    )
    audit['client_ip'] = entry.get('client_ip') or client_ip_from_request(request)
    audit['result'] = legacy_result_token(outcome=str(audit.get('outcome') or 'failed'))
    entry.clear()
    entry.update(audit)
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
        meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
        tenant = tenant_binding_from_meta(meta)
        if tenant:
            route['tenant'] = tenant
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
        exported = {**tool, 'name': export_name}
        merged.append({k: v for k, v in exported.items() if not str(k).startswith('_')})
    for service_id, tools in remote_by_service.items():
        for export_name, exported, route in iter_gateway_remote_exports(tools, service_id=service_id):
            if remember_route is not None:
                remember_route(export_name, route)
            merged.append({k: v for k, v in exported.items() if not str(k).startswith('_')})
    return merged


class PrefixingMcpServer(AggregatingMcpServer):
    """Same gateway, with an unambiguous service prefix on every downstream tool."""

    def _remember_route(
        self,
        export_name: str,
        service_id: str,
        downstream_name: str,
        *,
        tenant: dict[str, list[str]] | None = None,
    ) -> None:
        payload: dict[str, object] = {'service_id': service_id, 'downstream_name': downstream_name}
        if tenant:
            payload['tenant'] = tenant
        self._cache().set(
            f'mcp_gateway:route:{export_name}',
            payload,
            self._gateway.tools_cache_ttl_seconds,
        )

    def _meta_for_export_tool(self, export_name: str) -> dict:
        """OpenAPI `_meta` for the export plus optional tenant binding (for argument injection)."""
        tool_row = self._cached_export_tool(export_name)
        meta = dict(tool_row.get('_meta') or {}) if isinstance(tool_row, dict) else {}
        route = self._lookup_route(export_name)
        if isinstance(route, dict) and isinstance(route.get('tenant'), dict):
            tenant = route['tenant']
            if tenant.get('path_params'):
                meta['tenant_path_params'] = tenant['path_params']
            if tenant.get('query'):
                meta['tenant_query_fields'] = tenant['query']
            if tenant.get('body'):
                meta['tenant_body_fields'] = tenant['body']
        return meta

    def _inject_tool_call_arguments(
        self,
        export_name: str,
        arguments: dict,
        agent_claims: dict,
    ) -> dict:
        meta = self._meta_for_export_tool(export_name)
        return apply_tenant_to_arguments(arguments, agent_claims, meta)

    def _trusted_tool_operation(
        self,
        export_name: str,
        *,
        service_id: str,
        route: dict | None = None,
    ) -> tuple[dict | None, str | None]:
        """
        Return (tool_row, error_detail) for approval gate and audit.

        Uses only the gateway's registered tool catalog and route cache—never client path/method
        from the tools/call arguments.
        """
        tool_row = self._cached_export_tool(export_name)
        if not isinstance(tool_row, dict):
            return None, 'unknown_tool'
        meta = tool_row.get('_meta') if isinstance(tool_row.get('_meta'), dict) else {}
        method_raw = str(meta.get('method') or '').strip().upper()
        path_tmpl = str(meta.get('path') or '').strip()
        if not method_raw or not path_tmpl:
            return None, 'malformed_tool'
        if isinstance(route, dict):
            rsid = str(route.get('service_id') or '')
            if rsid and rsid != str(service_id):
                return None, 'route_mismatch'
            dns = str(route.get('downstream_name') or '').strip()
            if dns and service_id != self._gateway.local_service_id:
                mcp_url = self._gateway.get_service_urls().get(service_id)
                raw_list = self._cache().get(f'{_TOOLS_LIST_CACHE_PREFIX}{mcp_url}') if mcp_url else None
                if not isinstance(raw_list, list):
                    return None, 'route_mismatch'
                enriched = [normalize_mcp_tool(t) if isinstance(t, dict) else t for t in raw_list]
                expected = {str(nm) for nm, _exp, _rt in iter_gateway_remote_exports(enriched, service_id=service_id)}
                if export_name not in expected:
                    return None, 'route_mismatch'
        return tool_row, None

    def _tool_call_error_response(self, req_id, *, detail: str) -> JsonResponse:
        """JSON-RPC tool error: HTTP 200, isError true, allowlisted error_code only."""
        return JsonResponse(
            McpServer._result(
                req_id,
                {
                    'content': [{'type': 'text', 'text': 'Tool call rejected.'}],
                    'isError': True,
                    '_meta': {'error_code': 'mcp_tool_error', 'error_detail': detail},
                },
            )
        )

    def _prepare_tool_call_params(self, params: dict | None, agent_claims: dict, req_id) -> tuple[dict, JsonResponse | None]:
        call_params = dict(params or {})
        export_name = str(call_params.get('name') or '')
        local_name = self._local_tool_export_name(export_name)
        if local_name is not None:
            call_params['name'] = local_name
        arguments = call_params.get('arguments')
        if isinstance(arguments, dict):
            try:
                call_params['arguments'] = self._inject_tool_call_arguments(export_name, arguments, agent_claims)
            except McpToolArgumentError as exc:
                return call_params, JsonResponse(self._error(req_id, -32602, str(exc)))
        return call_params, None

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
        enriched = [normalize_mcp_tool(tool) if isinstance(tool, dict) else tool for tool in tools]
        for name, _tool, route in iter_gateway_remote_exports(enriched, service_id=service_id):
            if name == export_name:
                return route
        return None

    def _remember_routes_for_service_tools(self, service_id: str, tools: list[dict]) -> None:
        for export_name, _tool, route in iter_gateway_remote_exports(tools, service_id=service_id):
            self._remember_route(
                export_name,
                route['service_id'],
                route['downstream_name'],
                tenant=route.get('tenant'),
            )

    def _fetch_remote_tools_list(self, *, mcp_url: str, bearer_token: str) -> list[dict] | None:
        """
        Fetch downstream tools/list and cache **normalized** tools (preserve `_meta` for routing/audit).

        Parent ``public_mcp_tools`` strips `_meta` before cache; we need full registry metadata.
        """
        cache_key = f'{_TOOLS_LIST_CACHE_PREFIX}{mcp_url}'
        cached = self._cache().get(cache_key)
        if isinstance(cached, list) and cached:
            first = cached[0]
            if isinstance(first, dict) and isinstance(first.get('_meta'), dict):
                return cached
            # Legacy cache entries without `_meta`: refetch
            self._cache().delete(cache_key)
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}
        try:
            response = requests.post(
                mcp_url,
                json=payload,
                headers={
                    'Authorization': f'Bearer {bearer_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                timeout=self._gateway.downstream_timeout_seconds,
            )
        except (requests.RequestException, OSError) as exc:
            logger.warning('MCP gateway tools/list transport error url=%s err=%s', mcp_url, type(exc).__name__)
            return None
        if response.status_code >= 400:
            logger.warning('MCP gateway tools/list HTTP %s url=%s', response.status_code, mcp_url)
            return None
        try:
            body = response.json()
        except ValueError:
            logger.warning('MCP gateway tools/list invalid JSON url=%s', mcp_url)
            return None
        tools = (body.get('result') or {}).get('tools')
        if not isinstance(tools, list):
            logger.warning('MCP gateway tools/list missing tools url=%s', mcp_url)
            return None
        normalized = [normalize_mcp_tool(tool) if isinstance(tool, dict) else tool for tool in tools]
        self._cache().set(cache_key, normalized, self._gateway.tools_cache_ttl_seconds)
        return normalized

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
        meta = self._cache().get(f'mcp_gateway:route:{tool_name}')
        if isinstance(meta, dict) and meta.get('service_id') and meta.get('downstream_name'):
            return meta
        route = self._route_from_cached_tools_list(tool_name)
        if route is not None:
            self._remember_route(
                tool_name,
                route['service_id'],
                route['downstream_name'],
                tenant=route.get('tenant') if isinstance(route.get('tenant'), dict) else None,
            )
            return self._cache().get(f'mcp_gateway:route:{tool_name}')
        return None

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
        # Gateway only emits ``ai_*`` for this service's own catalog—never use a membership
        # snapshot here: a transient or alternate schema view must not turn a real local call
        # into ``unknown_tool`` (e2e: ``ai_list_services`` must resolve like ``list_services``).
        return downstream

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

    def _cached_export_tool(self, export_name: str) -> dict | None:
        """Resolve a tool row from the gateway export name (same rules as ``prefixed_tool_catalog``)."""
        local_id = self._gateway.local_service_id
        raw_export = str(export_name or '')
        # Local catalog: must mirror ``prefixed_tool_catalog`` export naming (sequential ``taken`` for collisions).
        if raw_export.startswith(f'{local_id}_'):
            taken: set[str] = set()
            for tool in tools_from_schema(self.schema_provider()):
                if not isinstance(tool, dict):
                    continue
                local_tool_name = str(tool.get('name') or '').strip()
                if not local_tool_name:
                    continue
                exp = gateway_export_name(local_id, local_tool_name, taken=taken)
                taken.add(exp)
                if exp == raw_export:
                    return normalize_mcp_tool(tool)
            return None
        local_name = self._local_tool_export_name(export_name)
        if local_name is not None:
            for tool in tools_from_schema(self.schema_provider()):
                if str(tool.get('name') or '') == local_name:
                    return normalize_mcp_tool(tool)
            return None
        service_id = self._service_id_from_export_name(export_name)
        if service_id is None:
            return None
        mcp_url = self._gateway.get_service_urls().get(service_id)
        if not mcp_url:
            return None
        tools = self._cache().get(f'{_TOOLS_LIST_CACHE_PREFIX}{mcp_url}')
        if not isinstance(tools, list):
            return None
        enriched = [normalize_mcp_tool(tool) if isinstance(tool, dict) else tool for tool in tools]
        for name, exported, _route in iter_gateway_remote_exports(enriched, service_id=service_id):
            if name == export_name:
                return exported
        return None

    def _gate_tool_call(
        self,
        request: HttpRequest,
        req_id,
        params: dict | None,
        agent_claims: dict,
        *,
        export_name: str,
        service_id: str,
        arguments: dict,
    ) -> JsonResponse | None:
        route = self._lookup_route(export_name)
        tool_row, err_detail = self._trusted_tool_operation(
            export_name,
            service_id=service_id,
            route=route if isinstance(route, dict) else None,
        )
        if err_detail is not None or tool_row is None:
            audit = build_call_audit_log(
                agent_claims=agent_claims,
                service_id=service_id,
                export_name=export_name,
                tool=None,
                method='GET',
                path='',
                log_result='error',
                status=200,
                is_error=True,
                error_code='mcp_tool_error',
            )
            audit['outcome'] = 'failed'
            audit['_mcp_audit_ready'] = True
            audit['duration_ms'] = 0
            if self.on_call:
                self.on_call(dict(audit))
            return self._tool_call_error_response(req_id, detail=err_detail or 'unknown_tool')
        meta = tool_row.get('_meta') if isinstance(tool_row.get('_meta'), dict) else {}
        method = str(meta.get('method') or 'GET').strip().upper()
        path = str(meta.get('path') or '').strip()
        outcome = enforce_tool_call_approval(
            request,
            req_id,
            params=params or {},
            agent_claims=agent_claims,
            export_name=export_name,
            service_id=service_id,
            tool=tool_row,
            method=method,
            path=path,
            arguments=arguments if isinstance(arguments, dict) else {},
        )
        if outcome.log and self.on_call:
            self.on_call(dict(outcome.log))
        if not outcome.proceed:
            return outcome.response
        return None

    def _maybe_forward_tool_call(self, request: HttpRequest, req_id, params, agent_claims):
        call_params, error = self._prepare_tool_call_params(params, agent_claims, req_id)
        if error is not None:
            return error
        export_name = str((params or {}).get('name') or '')
        local_name = self._local_tool_export_name(export_name)
        if local_name is not None:
            # Keep the gateway export name (e.g. ``ai_list_services``) for gating/audit; ``call_params``
            # already maps to the OpenAPI local tool name (``list_services``) for execution.
            return self._tools_call(
                request,
                req_id,
                call_params,
                agent_claims,
                gateway_export_name=export_name,
            )

        self._ensure_routes_for_export(export_name, agent_claims)
        route = self._lookup_route(export_name)
        if route is not None:
            arguments = call_params.get('arguments') if isinstance(call_params.get('arguments'), dict) else {}
            blocked = self._gate_tool_call(
                request,
                req_id,
                params,
                agent_claims,
                export_name=export_name,
                service_id=str(route['service_id']),
                arguments=arguments,
            )
            if blocked is not None:
                return blocked

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
        tool_row, err_detail = self._trusted_tool_operation(
            tool_name,
            service_id=str(route['service_id']),
            route=route,
        )
        if err_detail is not None or tool_row is None:
            audit = build_call_audit_log(
                agent_claims=agent_claims,
                service_id=str(route['service_id']),
                export_name=tool_name,
                tool=None,
                method='GET',
                path='',
                log_result='error',
                status=int(response.status_code),
                is_error=True,
                error_code='mcp_tool_error',
            )
            audit['outcome'] = 'failed'
            audit['_mcp_audit_ready'] = True
            audit['duration_ms'] = 0
            self.on_call(audit)
            return response
        meta = tool_row.get('_meta') if isinstance(tool_row.get('_meta'), dict) else {}
        m = str(meta.get('method') or 'GET').strip().upper()
        pth = str(meta.get('path') or '').strip()
        audit = build_call_audit_log(
            agent_claims=agent_claims,
            service_id=str(route['service_id']),
            export_name=tool_name,
            tool=tool_row,
            method=m,
            path=pth,
            log_result=None,
            status=int(response.status_code),
            is_error=is_error,
        )
        self.on_call(audit)
        return response

    def _tools_call(
        self,
        request,
        req_id,
        params,
        agent_claims,
        *,
        gateway_export_name: str | None = None,
    ):
        call_params, error = self._prepare_tool_call_params(params, agent_claims, req_id)
        if error is not None:
            return error
        export_name = str(gateway_export_name or (params or {}).get('name') or '')
        local_name = str(call_params.get('name') or '')
        arguments = call_params.get('arguments') if isinstance(call_params.get('arguments'), dict) else {}
        blocked = self._gate_tool_call(
            request,
            req_id,
            params,
            agent_claims,
            export_name=export_name or f'{self._gateway.local_service_id}_{local_name}',
            service_id=self._gateway.local_service_id,
            arguments=arguments,
        )
        if blocked is not None:
            return blocked

        import shellui_django.mcp.server as mcp_server_module

        bypass = bypass_shellui_write_gate()
        orig_decide = mcp_server_module.decide_write
        mcp_server_module.decide_write = patched_decide_write
        try:
            return self._using_connector_tool_catalog(
                lambda *args: super(PrefixingMcpServer, self)._tools_call(*args),
                request,
                req_id,
                call_params,
                agent_claims,
            )
        finally:
            mcp_server_module.decide_write = orig_decide
            reset_shellui_write_gate(bypass)

    def _aggregated_tools_list(self, req_id, agent_claims, params=None):
        agent = self._gateway.resolve_agent(agent_claims)
        if agent is None:
            return JsonResponse(self._error(req_id, -32603, 'Forbidden'))
        allowed = scope_service_ids(agent_claims) & set(agent.services_allowed or [])
        local = [normalize_mcp_tool(tool) for tool in tools_from_schema(self.schema_provider())]
        local_id = self._gateway.local_service_id
        remote: dict[str, list[dict]] = {}
        for service_id, mcp_url in self._gateway.get_service_urls().items():
            if service_id == local_id or service_id not in allowed:
                continue
            token = self._gateway.mint_downstream_token(agent, mcp_url)
            tools = self._fetch_remote_tools_list(mcp_url=mcp_url, bearer_token=token)
            if tools is not None:
                remote[service_id] = [normalize_mcp_tool(tool) for tool in tools]

        def remember(export_name: str, route: dict) -> None:
            self._remember_route(
                export_name,
                str(route['service_id']),
                str(route['downstream_name']),
                tenant=route.get('tenant') if isinstance(route.get('tenant'), dict) else None,
            )

        tools = prefixed_tool_catalog(
            local,
            remote,
            local_service_id=local_id,
            remember_route=remember,
        )
        company_label = resolve_company_label(agent_claims, agent=agent)
        tools = [apply_gateway_tool_presentation(tool, company_label=company_label) for tool in tools]
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
    claims_token = _mcp_agent_claims.set(claims)
    try:
        return _get_server().handle(request, agent_claims=claims)
    except DownstreamTokenError:
        return JsonResponse({'error': 'downstream_token_unavailable'}, status=503)
    finally:
        _mcp_agent_claims.reset(claims_token)
        _mcp_http_request.reset(token)


@csrf_exempt
def mcp_plain_endpoint(request: HttpRequest):
    """``/mcp`` has no company, so it never authenticates or picks a default tenant."""
    return JsonResponse({'error': 'company_required', 'message': PLAIN_MCP_MESSAGE}, status=404)
