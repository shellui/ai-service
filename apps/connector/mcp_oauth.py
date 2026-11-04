"""OAuth protected resource metadata (RFC 9728) for ai-service ``POST /c/<company_id>/mcp``."""

from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework.views import APIView

from apps.connector.mcp_authorize import protected_resource_authorize_extensions
from apps.connector.mcp_urls import PLAIN_MCP_MESSAGE, company_mcp_resource, public_origin


class OAuthProtectedResourceMetadataView(APIView):
    authentication_classes = []
    permission_classes = []

    @extend_schema(
        tags=['.well-known'],
        summary='OAuth protected resource metadata for MCP',
        responses={200: OpenApiTypes.OBJECT},
        exclude=True,
    )
    def get(self, request, company_id: int | None = None):
        if company_id is None or int(company_id) < 1:
            # No silent default company: the resource always names one.
            return JsonResponse({'error': 'company_required', 'message': PLAIN_MCP_MESSAGE}, status=404)
        auth_server = (
            getattr(settings, 'IDENTITY_ISSUER', '') or getattr(settings, 'IDENTITY_SERVICE_URL', '') or ''
        ).rstrip('/')
        if not auth_server:
            auth_server = public_origin(request)
        metadata = {
            'resource': company_mcp_resource(request, company_id),
            'authorization_servers': [auth_server],
            'bearer_methods_supported': ['header'],
        }
        metadata.update(protected_resource_authorize_extensions())
        return JsonResponse(metadata)
