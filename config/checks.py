"""Boot checks for region and global mode. Mixed settings are refused."""

from __future__ import annotations

from django.conf import settings
from django.core.checks import Error, register


@register()
def ai_service_mode_is_not_mixed(app_configs, **kwargs):
    mode = getattr(settings, 'AI_SERVICE_MODE', 'region')
    errors: list[Error] = []
    if mode == 'global' and getattr(settings, 'REGION_IDENTITY_CONFIGURED', False):
        errors.append(
            Error(
                'AI_SERVICE_MODE=global cannot also set regional identity or downstream MCP settings.',
                hint=(
                    'Unset IDENTITY_JWKS, IDENTITY_JWKS_FILE, IDENTITY_JWKS_URL, IDENTITY_SERVICE_URL, '
                    'IDENTITY_ISSUER, IDENTITY_AUDIENCE, STORAGE_SERVICE_URL, HOSTING_SERVICE_URL, '
                    'and EMAIL_SERVICE_API_KEY. Region mode is the process that calls those services.'
                ),
                id='ai_service.E001',
            )
        )
    if mode == 'region' and getattr(settings, 'GLOBAL_CONTROL_CONFIGURED', False):
        errors.append(
            Error(
                'AI_SERVICE_MODE=region cannot also set global MCP authorization settings.',
                hint=(
                    'Unset GLOBAL_IDENTITY_URL, GLOBAL_OIDC_CLIENT_ID, GLOBAL_OIDC_CLIENT_SECRET, '
                    'and SAAS_API_AUDIENCE, or set AI_SERVICE_MODE=global on a separate process.'
                ),
                id='ai_service.E002',
            )
        )
    return errors
