"""URL configuration for ai-service."""

from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from django.views.decorators.clickjacking import xframe_options_exempt
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from apps.authapi.ai_jwks_views import AiServiceJwksView
from apps.connector.mcp_oauth import OAuthProtectedResourceMetadataView
from apps.connector.mcp_views import mcp_endpoint, mcp_plain_endpoint

from . import views

urlpatterns = [
    path('', views.root, name='root'),
    path('health/live', views.health_live, name='health-live'),
    path('.well-known/jwks.json', AiServiceJwksView.as_view(), name='jwks'),
    # RFC 9728 path insertion: /.well-known/oauth-protected-resource + /c/<id>/mcp.
    # MCP clients also request the same path with a trailing slash.
    path(
        '.well-known/oauth-protected-resource/c/<int:company_id>/mcp',
        OAuthProtectedResourceMetadataView.as_view(),
        name='mcp-oauth-protected-resource',
    ),
    path(
        '.well-known/oauth-protected-resource/c/<int:company_id>/mcp/',
        OAuthProtectedResourceMetadataView.as_view(),
        name='mcp-oauth-protected-resource-slash',
    ),
    # Clients that append the well-known suffix to the MCP URL (pathname + /.well-known/...).
    path(
        'c/<int:company_id>/mcp/.well-known/oauth-protected-resource',
        OAuthProtectedResourceMetadataView.as_view(),
        name='mcp-oauth-protected-resource-suffix',
    ),
    path(
        'c/<int:company_id>/mcp/.well-known/oauth-protected-resource/',
        OAuthProtectedResourceMetadataView.as_view(),
        name='mcp-oauth-protected-resource-suffix-slash',
    ),
    path(
        '.well-known/oauth-protected-resource',
        OAuthProtectedResourceMetadataView.as_view(),
        name='mcp-oauth-protected-resource-plain',
    ),
    path('c/<int:company_id>/mcp', mcp_endpoint, name='mcp'),
    path('mcp', mcp_plain_endpoint, name='mcp-plain'),
    path('ai/v1/', include('apps.connector.urls')),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path(
        'api/docs/',
        xframe_options_exempt(SpectacularSwaggerView.as_view(url_name='schema')),
        name='swagger-ui',
    ),
    path(
        'api/docs/redoc/',
        xframe_options_exempt(SpectacularRedocView.as_view(url_name='schema')),
        name='redoc',
    ),
]

if getattr(settings, 'DJANGO_ADMIN_ENABLED', True):
    urlpatterns.insert(1, path('admin/', admin.site.urls))

handler400 = 'config.errors.bad_request'
handler403 = 'config.errors.permission_denied'
handler404 = 'config.errors.page_not_found'
handler500 = 'config.errors.server_error'
