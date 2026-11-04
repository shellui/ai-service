"""Aggregated MCP gateway at ai-service ``POST /mcp``."""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from shellui_django.mcp.gateway import AggregatingMcpServer, McpGatewayConfig
from shellui_django.mcp.resources import access_token_audience_matches

from apps.authapi.agent_tokens import authenticate_agent_bearer, mcp_resource_audience
from apps.connector.agent_record import AgentRecord
from apps.connector.downstream_tokens import DownstreamTokenError, mint_downstream_access_token
from apps.connector.mcp_identity import agent_is_revoked, forward_call_log, identity_revocation_unavailable
from apps.connector.services import configured_service_urls, downstream_resource_for

_server: AggregatingMcpServer | None = None


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
            instructions_title='Shellui AI MCP gateway.',
        )
        _server = AggregatingMcpServer(
            gateway=gateway,
            schema_provider=_schema,
            urlconf=settings.ROOT_URLCONF,
            service_name='ai',
            identity_revocation_check=agent_is_revoked,
            on_call=forward_call_log,
        )
    return _server


def _agent_claims(request: HttpRequest) -> dict | None:
    header = request.headers.get('Authorization', '')
    if not header.lower().startswith('bearer '):
        return None
    raw = header.split(' ', 1)[1].strip()
    expected_resource = mcp_resource_audience(request)
    result = authenticate_agent_bearer(raw, expected_resource=expected_resource)
    if not result:
        return None
    principal, claims = result
    if not access_token_audience_matches(claims, expected_resource):
        return None
    request.user = principal
    drf_request = Request(request)
    drf_request.user = principal
    return dict(claims)


@csrf_exempt
def mcp_endpoint(request: HttpRequest):
    claims = _agent_claims(request)
    if claims is not None and identity_revocation_unavailable():
        return JsonResponse({'error': 'identity_unavailable'}, status=503)
    try:
        return _get_server().handle(request, agent_claims=claims)
    except DownstreamTokenError:
        return JsonResponse({'error': 'downstream_token_unavailable'}, status=503)
