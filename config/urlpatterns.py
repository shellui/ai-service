"""Route tables for region mode and global mode."""

from django.conf import settings
from django.urls import include, path
from django.views.decorators.clickjacking import xframe_options_exempt
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from apps.authapi.ai_jwks_views import AiServiceJwksView
from apps.connector.mcp_approval_decided_views import McpApprovalDecidedView
from apps.connector.mcp_oauth import OAuthProtectedResourceMetadataView
from apps.connector.mcp_views import mcp_endpoint, mcp_plain_endpoint
from apps.global_mcp.device import device_authorization, device_verify
from apps.global_mcp.mcp_views import global_mcp_endpoint
from apps.global_mcp.oauth_views import (
    approval_page,
    authorization_server_metadata,
    mcp_authorize,
    mcp_consent,
    mcp_register,
    mcp_token,
    protected_resource_metadata,
    signin_complete,
)

from . import views


def _docs():
    return [
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


def _common():
    patterns = [
        path('', views.root, name='root'),
        path('health/live', views.health_live, name='health-live'),
        path('.well-known/jwks.json', AiServiceJwksView.as_view(), name='jwks'),
    ]
    if getattr(settings, 'DJANGO_ADMIN_ENABLED', True):
        from django.contrib import admin

        patterns.insert(1, path('admin/', admin.site.urls))
    return patterns


def region_urlpatterns():
    return [
        *_common(),
        path(
            'internal/mcp-approval-decided',
            McpApprovalDecidedView.as_view(),
            name='internal-mcp-approval-decided',
        ),
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
        *_docs(),
    ]


def global_urlpatterns():
    return [
        *_common(),
        path(
            '.well-known/oauth-authorization-server',
            authorization_server_metadata,
            name='global-oauth-authorization-server',
        ),
        path(
            '.well-known/oauth-protected-resource',
            protected_resource_metadata,
            name='global-oauth-protected-resource',
        ),
        path(
            '.well-known/oauth-protected-resource/mcp',
            protected_resource_metadata,
            name='global-oauth-protected-resource-mcp',
        ),
        path(
            'mcp/.well-known/oauth-protected-resource',
            protected_resource_metadata,
            name='global-oauth-protected-resource-suffix',
        ),
        path('oauth/mcp/register', mcp_register, name='global-oauth-register'),
        path('oauth/mcp/authorize', mcp_authorize, name='global-oauth-authorize'),
        path('oauth/mcp/signin/complete', signin_complete, name='global-oauth-signin-complete'),
        path('oauth/mcp/consent', mcp_consent, name='global-oauth-consent'),
        path('oauth/mcp/token', mcp_token, name='global-oauth-token'),
        path('oauth/mcp/device/code', device_authorization, name='global-oauth-device-code'),
        path('oauth/mcp/device', device_verify, name='global-oauth-device'),
        path('oauth/mcp/approvals/<uuid:approval_id>', approval_page, name='global-oauth-approval'),
        path('mcp', global_mcp_endpoint, name='global-mcp'),
        path('ai/v1/', include('apps.connector.urls')),
        *_docs(),
    ]
