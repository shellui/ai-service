"""Public HTTP API for ai-service."""

from __future__ import annotations

from django.http import JsonResponse
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from shellui_django.mcp.decorators import mcp_expose_tool

from apps.connector.services import list_mcp_services


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
        responses={200: OpenApiResponse(description='Service catalog')},
    )
    @mcp_expose_tool(name='list_services', description='Return MCP URLs for connected Shellui services.')
    def get(self, request):
        return Response({'services': list_mcp_services()})
