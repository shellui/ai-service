"""Single source of truth for ai-service environment variables."""

from __future__ import annotations

from dataclasses import dataclass

PLACEHOLDER = 'change-me'


@dataclass(frozen=True)
class Var:
    name: str
    default: str = ''
    group: str = ''


@dataclass(frozen=True)
class Required:
    name: str
    comment: str


REQUIRED = (
    Required('SECRET_KEY', 'Signs sessions and CSRF tokens. At least 50 characters. Generated.'),
    Required('DEBUG', 'Production mode.'),
    Required('ALLOWED_HOSTS', 'Public host names, comma-separated, no scheme.'),
    Required('CSRF_TRUSTED_ORIGINS', 'Full HTTPS origin of this service.'),
    Required('IDENTITY_SERVICE_URL', 'identity-service origin. JWKS at {url}/.well-known/jwks.json.'),
    Required('IDENTITY_ISSUER', 'Must match identity-service JWT_ISSUER.'),
    Required('IDENTITY_AUDIENCE', 'Must match identity-service JWT_AUDIENCE.'),
    Required('REDIS_URL', 'Shared cache for MCP gateway tool catalogs and rate limits.'),
    Required('POSTGRES_DATABASE_URL', 'PostgreSQL DSN. Leave empty to use SQLite.'),
    Required(
        'AI_SERVICE_SIGNING_KEY',
        'RSA PEM for RS256 downstream delegation (or set AI_SERVICE_SIGNING_KEY_FILE). '
        'Run: python manage.py generate_signing_key',
    ),
    Required('AI_SERVICE_SIGNING_KID', 'JWKS kid from generate_signing_key.'),
    Required(
        'AI_SERVICE_ISSUER',
        'JWT iss on delegation requests to identity (this service public https origin).',
    ),
)

OPTIONAL = (
    Var('LOG_LEVEL', 'INFO', 'Runtime'),
    Var('SETUP_TOKEN', ''),
    Var('DJANGO_ADMIN_ENABLED', 'true'),
    Var('AI_SERVICE_PORT', '8006', 'Docker Compose host port'),
    Var('SQLITE_PATH', 'db.sqlite3', 'Database'),
    Var('POSTGRES_SSL_REQUIRE', 'true'),
    Var('IDENTITY_JWKS_FILE', '', 'Pin identity JWKS in production.'),
    Var('IDENTITY_JWKS', ''),
    Var('IDENTITY_JWKS_URL', ''),
    Var('JWKS_CACHE_TTL', '900'),
    Var('JWKS_TIMEOUT', '15'),
    Var('JWKS_RETRIES', '2'),
    Var('JWT_ALGORITHMS', 'RS256'),
    Var('JWT_HS256_FALLBACK_SECRET', ''),
    Var('ALLOW_JWT_HS256_FALLBACK', 'false'),
    Var('AI_SERVICE_SIGNING_KEY_FILE', '', 'RS256 delegation to identity'),
    Var('STORAGE_SERVICE_URL', '', 'Downstream MCP origins'),
    Var('HOSTING_SERVICE_URL', ''),
    Var('EMAIL_SERVICE_URL', 'https://email.shellui.com'),
    Var('EMAIL_SERVICE_API_KEY', ''),
    Var('EMAIL_SERVICE_ALLOW_PRIVATE', 'false'),
    Var('SAAS_SERVICE_URL', ''),
    Var('STORAGE_SERVICE_PUBLIC_URL', '', 'Public origins for downstream MCP token resources, when the URLs above are internal'),
    Var('HOSTING_SERVICE_PUBLIC_URL', ''),
    Var('EMAIL_SERVICE_PUBLIC_URL', ''),
    Var('SAAS_SERVICE_PUBLIC_URL', ''),
    Var('AI_SERVICE_MODE', 'region', 'region (default) or global. One image, chosen at boot.'),
    Var('AI_PUBLIC_URL', '', 'Public origin of this gateway. Region MCP URL is /c/<company_id>/mcp. Global MCP URL is /mcp.'),
    Var('GLOBAL_IDENTITY_URL', '', 'identity-global public origin for the OIDC login page'),
    Var('GLOBAL_IDENTITY_INTERNAL_URL', '', 'identity-global origin for the token and userinfo calls. Defaults to GLOBAL_IDENTITY_URL'),
    Var('GLOBAL_REGION_INTERNAL_URLS', '', 'Comma list of public=internal origins for server-side region calls'),
    Var('GLOBAL_IDENTITY_ISSUER', '', 'iss of identity-global tokens'),
    Var('GLOBAL_IDENTITY_AUDIENCE', 'shellui', 'aud of identity-global access tokens (dashboard JWT_AUDIENCE)'),
    Var('GLOBAL_IDENTITY_JWKS', '', 'Pinned identity-global JWKS JSON'),
    Var('GLOBAL_IDENTITY_JWKS_URL', '', 'Fetch URL when GLOBAL_IDENTITY_JWKS is empty'),
    Var('GLOBAL_OIDC_CLIENT_ID', '', 'Confidential client id in identity-global OIDC_CLIENTS'),
    Var('GLOBAL_OIDC_CLIENT_SECRET', '', 'Confidential client secret'),
    Var('GLOBAL_OIDC_REDIRECT_URI', '', 'https://ai.shellui.com/oauth/mcp/signin/complete'),
    Var('SAAS_SERVICE_INTERNAL_URL', '', 'saas origin for server-side REST. Defaults to SAAS_SERVICE_URL'),
    Var('SAAS_API_AUDIENCE', '', 'aud on saas API tokens. Typically https://saas.shellui.com/api'),
    Var('GLOBAL_MCP_ACCESS_TOKEN_TTL_SECONDS', '3600', 'Global MCP access token lifetime'),
    Var('GLOBAL_MCP_REFRESH_TOKEN_TTL_SECONDS', '2592000', 'Rotating refresh token lifetime, 30 days'),
    Var('GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE', 'shellui-agents', 'aud on RFC 8693 subject tokens. Must match region identity'),
    Var('MCP_APPROVAL_SESSION_TTL_SECONDS', '60', 'Non-destructive approval session grant'),
    Var('MCP_SETUP_APPROVAL_SESSION_TTL_SECONDS', '900', 'Setup-flow approval session grant, clamped to 600-900'),
    Var('MCP_DYNAMIC_CLIENT_REGISTRATION', 'true', 'POST /oauth/mcp/register'),
    Var('GLOBAL_COMPANY_WAIT_SECONDS', '60', 'ai_wait_for_company bound'),
    Var('GLOBAL_COMPANY_POLL_SECONDS', '2', 'ai_wait_for_company poll interval'),
    Var(
        'REGIONAL_EXCHANGE_ALLOWED_HOSTS',
        '',
        'Regional exchange hosts: exact host, host:port, .suffix, or *.suffix. https only when DEBUG=false. Empty allows none.',
    ),
    Var('MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS', '30', 'Aggregated MCP gateway'),
    Var('MCP_TOOLS_LIST_MODE', 'discovery', 'tools/list default: discovery or all'),
    Var('MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', '5'),
    Var(
        'MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS',
        '900',
        'Max exp-iat on signed approval assertions to identity (setup flows need 600–900s)',
    ),
    Var('MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS', '600', 'Setup session Allow lower bound (signed claims)'),
    Var('MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS', '900', 'Setup session Allow upper bound (signed claims)'),
    Var('MCP_APPROVAL_CHANNEL_BY_COMPANY', ''),
    Var(
        'MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS',
        '90',
        'Seconds the approval SSE wait holds for a decide wake. Keep this under GUNICORN_TIMEOUT.',
    ),
    Var('MCP_CALL_LOG_RETENTION_DAYS', '90', 'Days to keep gateway MCP tool-call logs'),
    Var('MCP_RATE_LIMIT_AGENT', '120'),
    Var('CORS_ALLOW_ALL_ORIGINS', 'true', 'CORS and HTTPS'),
    Var('CORS_ALLOW_CREDENTIALS', 'false'),
    Var('CORS_ALLOWED_ORIGINS', ''),
    Var('CORS_ALLOW_PRIVATE_NETWORK', 'true'),
    Var('SECURE_SSL_REDIRECT', 'true'),
    Var('SECURE_HSTS_SECONDS', '31536000'),
    Var('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'true'),
    Var('SECURE_HSTS_PRELOAD', 'false'),
    Var('SESSION_COOKIE_SECURE', 'true'),
    Var('CSRF_COOKIE_SECURE', 'true'),
    Var('OTEL_EXPORTER_OTLP_ENDPOINT', '', 'OpenTelemetry. Empty leaves export off.'),
    Var('OTEL_EXPORTER_OTLP_HEADERS', ''),
    Var('OTEL_EXPORTER_OTLP_PROTOCOL', 'http/protobuf'),
    Var('OTEL_SERVICE_NAME', 'ai-service'),
    Var('OTEL_RESOURCE_ATTRIBUTES', ''),
    Var('SENTRY_DSN', '', 'Sentry'),
    Var('SENTRY_ENVIRONMENT', 'production'),
    Var('SENTRY_RELEASE', ''),
    Var('SENTRY_TRACES_SAMPLE_RATE', '0'),
    Var('GUNICORN_WORKERS', '2', 'Gunicorn'),
    Var('GUNICORN_THREADS', '2'),
    Var('GUNICORN_TIMEOUT', '120'),
    Var('GUNICORN_GRACEFUL_TIMEOUT', '30'),
    Var('GUNICORN_KEEP_ALIVE', '75'),
    Var('GUNICORN_MAX_REQUESTS', '1000'),
    Var('GUNICORN_MAX_REQUESTS_JITTER', '200'),
)

COMPOSE_ONLY = frozenset({'AI_SERVICE_PORT'})


def all_names() -> set[str]:
    return {item.name for item in REQUIRED} | {item.name for item in OPTIONAL} | COMPOSE_ONLY


def optional_lines(skip: frozenset[str] = frozenset()) -> list[str]:
    lines: list[str] = []
    for var in OPTIONAL:
        if var.group:
            lines.extend(['', f'# {var.group}'])
        if var.name in skip:
            continue
        lines.append(f'# {var.name}={var.default}')
    return lines


_EXAMPLE_HEADER = """\
# ai-service settings. Full reference: docs/configuration.md
# Shellui local stack: docs/devstack.md
# Generated from config/env_registry.py: python manage.py generate_env --example > .env.example
# Production: python manage.py generate_env --host ai.example.com
# Copy to .env for local runs. Commented-out lines show the default the code uses.

# Required
SECRET_KEY=
DEBUG=true
ALLOWED_HOSTS=localhost,127.0.0.1
IDENTITY_SERVICE_URL=http://localhost:8001
IDENTITY_JWKS_URL=http://localhost:8001/.well-known/jwks.json

# Required when DEBUG=false (production)
IDENTITY_ISSUER=
IDENTITY_AUDIENCE=
REDIS_URL=
CSRF_TRUSTED_ORIGINS=

# Optional (defaults shown)"""


def render_example() -> str:
    return '\n'.join([_EXAMPLE_HEADER, *optional_lines()]) + '\n'
