"""Public HTTP API for ai-service."""

from __future__ import annotations

from django.http import JsonResponse
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_django.mcp.decorators import mcp_expose_tool

from apps.connector.mcp_discovery import enrich_service_rows
from apps.connector.services import list_mcp_services


def _service_directory() -> list[dict]:
    """Summaries always. Counts only after tools/list or search has cached this company.

    A cold ``ai_list_services`` call does not fetch downstream. Search and describe do.
    """
    from apps.connector.mcp_views import _get_server, _mcp_agent_claims

    claims = _mcp_agent_claims.get()
    server = _get_server()
    if isinstance(claims, dict) and server._remote_catalog_cached(claims):
        return enrich_service_rows(
            list_mcp_services(),
            server._cached_export_tools(claims),
            include_counts=True,
        )
    return enrich_service_rows(list_mcp_services(), None, include_counts=False)


class HealthView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(tags=['health'], responses={200: OpenApiResponse(description='Service health')}, auth=[])
    def get(self, request):
        from django.conf import settings

        payload = {'status': 'ok', 'service': 'ai-service', 'version': settings.VERSION}
        user = getattr(request, 'user', None)
        if user is not None and getattr(user, 'is_authenticated', False):
            payload.update(
                {
                    'identity_jwks_source': settings.IDENTITY_JWKS_SOURCE or 'url',
                    'identity_jwks_url': settings.IDENTITY_JWKS_URL,
                }
            )
        return JsonResponse(payload)


class McpServicesListView(APIView):
    """MCP tool: connected Shellui services and their ``/mcp`` URLs."""

    @extend_schema(
        tags=['mcp-tools'],
        operation_id='api_v1_mcp_services_list',
        summary='List connected MCP services',
        responses={200: OpenApiResponse(description='Service catalog with a one-line summary, tool count, and example tasks')},
    )
    @mcp_expose_tool(name='list_services', description='Return MCP URLs for connected Shellui services.')
    def get(self, request):
        return Response({'services': _service_directory()})
