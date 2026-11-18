"""OAuth protected resource metadata (RFC 9728) for ai-service ``POST /c/<company_id>/mcp``."""

from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework.views import APIView

from apps.connector.mcp_authorize import protected_resource_authorize_extensions
from apps.connector.mcp_urls import PLAIN_MCP_MESSAGE, company_mcp_resource

# OAuth scope clients request. Not the JWT ``scope`` claim (that lists service ids).
MCP_OAUTH_SCOPE = 'mcp'


def identity_authorization_server() -> str:
    """Identity's metadata ``issuer``.

    ``IDENTITY_ISSUER`` is that string (identity ``JWT_ISSUER``, trailing slash removed
    the same way identity publishes ``issuer``). In the local stack it is
    ``http://localhost:8001``. ``IDENTITY_SERVICE_URL`` is only a fallback when the
    public issuer was not split from the service origin (host-local ``.env``). Never
    advertise this gateway: clients would run OAuth against the wrong host.
    """
    issuer = str(getattr(settings, 'IDENTITY_ISSUER', '') or '').strip().rstrip('/')
    if issuer:
        return issuer
    return str(getattr(settings, 'IDENTITY_SERVICE_URL', '') or '').strip().rstrip('/')


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
            # The origin-root well-known URL is this case (MCP clients probe it
            # only after the path-inserted URL). It must not invent a company.
            return JsonResponse({'error': 'company_required', 'message': PLAIN_MCP_MESSAGE}, status=404)
        auth_server = identity_authorization_server()
        if not auth_server:
            return JsonResponse({'error': 'authorization_server_unconfigured'}, status=503)
        # RFC 9728 fields only. device_authorization_endpoint lives on identity's
        # authorization-server metadata, not on this document.
        metadata = {
            'resource': company_mcp_resource(request, company_id),
            'authorization_servers': [auth_server],
            'scopes_supported': [MCP_OAUTH_SCOPE],
            'bearer_methods_supported': ['header'],
        }
        metadata.update(protected_resource_authorize_extensions())
        return JsonResponse(metadata)
