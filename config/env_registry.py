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
    Var('AI_PUBLIC_URL', '', 'Public origin of this gateway; the MCP URL is /c/<company_id>/mcp'),
    Var('MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS', '30', 'Aggregated MCP gateway'),
    Var('MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', '5'),
    Var(
        'MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS',
        '900',
        'Max exp-iat on signed approval assertions to identity (setup flows need 600–900s)',
    ),
    Var('MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS', '600', 'Setup session Allow lower bound (signed claims)'),
    Var('MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS', '900', 'Setup session Allow upper bound (signed claims)'),
    Var(
        'MCP_SESSION_GRANT_INDEX_MAX_SECONDS',
        '3600',
        'Upper bound on Django cache TTL for MCP session-grant map keys (revocation invalidation index)',
    ),
    Var(
        'MCP_SETUP_REQUIRES_ABSOLUTE_EXPIRY',
        'false',
        'After identity #135: reject setup_flow without setup_expires_at on the regional token',
    ),
    Var(
        'MCP_SESSION_GRANT_REQUIRES_ABSOLUTE_EXPIRES_AT',
        'false',
        'After identity #135: reject session-check allow when setup_flow lacks expires_at + setup cap',
    ),
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
