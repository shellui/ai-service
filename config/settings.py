"""
Django settings for Shellui ai-service.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from datetime import timedelta
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / '.env')


def _env_csv(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(',') if item.strip()]


_DURATION_RE = re.compile(r'^(\d+(?:\.\d+)?)(s|m|h|d)?$', re.IGNORECASE)
_DURATION_UNITS = {
    's': 1,
    'm': 60,
    'h': 3600,
    'd': 86400,
}


def _env_duration(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    match = _DURATION_RE.fullmatch(raw)
    if not match:
        raise ImproperlyConfigured(
            f'{name} must be a duration like 30s, 5m, 2h, or 7d (bare integer = seconds). '
            f'Got: {raw!r}'
        )
    amount = float(match.group(1))
    unit = (match.group(2) or 's').lower()
    if amount <= 0:
        raise ImproperlyConfigured(f'{name} must be greater than zero. Got: {raw!r}')
    return timedelta(seconds=amount * _DURATION_UNITS[unit])


def _env_float(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ImproperlyConfigured(f'{name} must be a number. Got: {raw!r}') from exc


def _env_int(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ImproperlyConfigured(f'{name} must be an integer. Got: {raw!r}') from exc


def _env_bool(name, default: bool) -> bool:
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    return raw.lower() in {'1', 'true', 'yes', 'on'}


def _caches_config(redis_url: str) -> dict:
    """
    Shared cache for auth rate limits, access-token denylist, and activity throttles.

    When ``REDIS_URL`` is set, use Django's Redis backend (requires the ``redis`` package).
    Otherwise use in-process LocMem (fine for single-process dev; not shared across Gunicorn workers).
    """
    if redis_url:
        return {
            'default': {
                'BACKEND': 'django.core.cache.backends.redis.RedisCache',
                'LOCATION': redis_url,
            }
        }
    return {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'identity-service-auth',
        }
    }


_secret_key = os.getenv('SECRET_KEY', '').strip()
if not _secret_key:
    raise ImproperlyConfigured(
        '\n'
        'SECRET_KEY is not set. ai-service cannot start.\n'
        '\n'
        'How to fix:\n'
        '  Local: cp .env.example .env, then set SECRET_KEY in .env.\n'
        '  Production: python manage.py generate_env --host ai.example.com\n'
        '  prints every required setting with a fresh SECRET_KEY.\n'
    )
SECRET_KEY = _secret_key

DEBUG = os.getenv('DEBUG', 'false').strip().lower() in {'1', 'true', 'yes', 'on'}
# One-time web bootstrap token for creating the first superuser when DEBUG=false.
# When unset, use `manage.py createsuperuser` instead of the public form at `/`.
SETUP_TOKEN = os.getenv('SETUP_TOKEN', '').strip()
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG' if DEBUG else 'INFO').strip().upper() or (
    'DEBUG' if DEBUG else 'INFO'
)

ALLOWED_HOSTS = _env_csv('ALLOWED_HOSTS', ('localhost', '127.0.0.1'))
CSRF_TRUSTED_ORIGINS = _env_csv(
    'CSRF_TRUSTED_ORIGINS',
    (
        'http://localhost:8006',
        'http://127.0.0.1:8006',
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:5174',
        'http://127.0.0.1:5174',
        'http://localhost:5175',
        'http://127.0.0.1:5175',
        'https://admin.shellui.com',
    ),
)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')


def _project_version():
    pyproject = BASE_DIR / 'pyproject.toml'
    with pyproject.open('rb') as fh:
        data = tomllib.load(fh)
    version = str(data.get('project', {}).get('version', '')).strip()
    if not version:
        raise ImproperlyConfigured(f'project.version is missing in {pyproject}')
    return version


VERSION = _project_version()

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'drf_spectacular',
    'drf_spectacular_sidecar',
    'config.apps.ConfigConfig',
    'apps.authapi',
    'apps.connector',
    'apps.keys',
]

REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'apps.authapi.mcp_schema.McpAutoSchema',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'apps.authapi.authentication.IdentityJWKSAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'apps.authapi.permissions.IsAuthenticatedPrincipal',
    ],
    'EXCEPTION_HANDLER': 'config.exceptions.exception_handler',
    # JSON only: browsers get the same error body as API clients, never the
    # browsable API page. Views that need another format set renderer_classes.
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Shellui AI API',
    'DESCRIPTION': (
        'Aggregated MCP connector for Shellui agents. '
        'Authenticate with a Bearer JWT issued by identity-service OAuth for this service `/mcp` resource.'
    ),
    'VERSION': VERSION,
    'SERVE_INCLUDE_SCHEMA': False,
    # ReDoc and Swagger UI ship from the sidecar package, pinned with the app, and are served
    # from our own static files. The CDN's redoc@latest moved to 3.x (an ES module) and broke
    # the page, so nothing on the docs pages loads from an unpinned CDN anymore.
    'REDOC_DIST': 'SIDECAR',
    'SWAGGER_UI_DIST': 'SIDECAR',
    'SWAGGER_UI_FAVICON_HREF': 'SIDECAR',
    'SWAGGER_UI_SETTINGS': {
        'persistAuthorization': True,
    },
    'TAGS': [
        {'name': 'health', 'description': 'Service health checks.'},
        {'name': 'mcp-tools', 'description': 'Operations exposed to Shellui MCP agents.'},
    ],
    'PREPROCESSING_HOOKS': ['apps.authapi.spectacular_hooks.preprocessing_exclude_internal_endpoints'],
    'POSTPROCESSING_HOOKS': ['apps.authapi.spectacular_hooks.postprocess_mcp_tool_tags'],
}

# Outbound signed assertions to identity-service MCP internal APIs (approvals, call logs).
SIMPLE_JWT = {
    'SIGNING_KEY': _secret_key,
    'ALGORITHM': 'HS256',
    'ISSUER': os.getenv('IDENTITY_ISSUER', '').strip() or None,
}

MCP_RATE_LIMITS = {
    'default': {'limit': 120, 'window': 60},
    'mcp_agent': {'limit': _env_int('MCP_RATE_LIMIT_AGENT', 120), 'window': 60},
}

MIDDLEWARE = [
    # Outermost: every response, including /health/live and redirects, carries X-Request-ID.
    'config.request_context.RequestIdMiddleware',
    # First: /health/live answers before host checks, https redirect, sessions and DB.
    'config.liveness.LivenessMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Branded page for browsers, JSON under the API prefixes (config/errors.py).
CSRF_FAILURE_VIEW = 'config.errors.csrf_failure'

# Shared cache, and the broker for the scheduled jobs. Required when DEBUG=false:
# authapi.E004 and the Docker entrypoint refuse to start without it.
REDIS_URL = os.getenv('REDIS_URL', '').strip()
CACHES = _caches_config(REDIS_URL)

POSTGRES_DATABASE_URL = os.getenv('POSTGRES_DATABASE_URL', '').strip()

POSTGRES_SSL_REQUIRE = _env_bool('POSTGRES_SSL_REQUIRE', not DEBUG)

if POSTGRES_DATABASE_URL:
    DATABASES = {
        'default': dj_database_url.parse(
            POSTGRES_DATABASE_URL,
            conn_max_age=600,
            ssl_require=POSTGRES_SSL_REQUIRE,
        )
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': os.getenv('SQLITE_PATH', str(BASE_DIR / 'db.sqlite3')),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

if DEBUG:
    # Local dev: serve assets from STATICFILES_DIRS without collectstatic.
    WHITENOISE_USE_FINDERS = True
    WHITENOISE_AUTOREFRESH = True

STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedStaticFilesStorage',
    },
}

TEST_RUNNER = 'config.test_runner.IsolatedMediaDiscoverRunner'

# ---------------------------------------------------------------------------
# Identity / JWKS authentication
#
# Prefer a local JWKS document in production (no runtime HTTP to identity):
#   IDENTITY_JWKS_FILE=/app/data/jwks.json
#   IDENTITY_JWKS={"keys":[...]}
# Local/dev can still fetch:
#   IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json
# ---------------------------------------------------------------------------
def _parse_jwks_document(raw: str, *, source: str) -> dict:
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ImproperlyConfigured(f'{source} is not valid JSON: {exc}') from exc
    if not isinstance(document, dict) or not isinstance(document.get('keys'), list):
        raise ImproperlyConfigured(f'{source} must be a JWKS object with a "keys" array.')
    if not document['keys']:
        raise ImproperlyConfigured(f'{source} has an empty "keys" array.')
    return document


def _load_static_jwks() -> tuple[dict | None, str | None, str | None]:
    """Return (document, source, file_path). source is 'file', 'env', or None."""
    file_path = os.getenv('IDENTITY_JWKS_FILE', '').strip()
    if file_path:
        path = Path(file_path)
        if not path.is_absolute():
            path = BASE_DIR / path
        if not path.is_file():
            raise ImproperlyConfigured(f'IDENTITY_JWKS_FILE not found: {path}')
        return _parse_jwks_document(path.read_text(encoding='utf-8'), source=str(path)), 'file', str(path)

    raw = os.getenv('IDENTITY_JWKS', '').strip()
    if raw:
        return _parse_jwks_document(raw, source='IDENTITY_JWKS'), 'env', None
    return None, None, None


def _resolve_identity_jwks_url() -> str:
    explicit = os.getenv('IDENTITY_JWKS_URL', '').strip()
    if explicit:
        return explicit.rstrip('/')
    base = os.getenv('IDENTITY_SERVICE_URL', '').strip().rstrip('/')
    if base:
        return f'{base}/.well-known/jwks.json'
    return 'http://localhost:8000/.well-known/jwks.json'


IDENTITY_JWKS_DOCUMENT, IDENTITY_JWKS_SOURCE, IDENTITY_JWKS_FILE = _load_static_jwks()
IDENTITY_SERVICE_URL = os.getenv('IDENTITY_SERVICE_URL', '').strip().rstrip('/') or None
if IDENTITY_JWKS_DOCUMENT is not None:
    IDENTITY_JWKS_URL = os.getenv('IDENTITY_JWKS_URL', '').strip().rstrip('/') or None
else:
    IDENTITY_JWKS_URL = _resolve_identity_jwks_url()
    if not IDENTITY_JWKS_URL.startswith(('http://', 'https://')):
        raise ImproperlyConfigured(
            f'IDENTITY_JWKS_URL must be an absolute http(s) URL. Got: {IDENTITY_JWKS_URL!r}\n'
            'Prefer a local document in production:\n'
            '  IDENTITY_JWKS_FILE=/app/data/jwks.json\n'
            '  IDENTITY_JWKS={"keys":[...]}\n'
            'Or a fetch URL for local/dev:\n'
            '  IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json'
        )
IDENTITY_ISSUER = os.getenv('IDENTITY_ISSUER', '').strip() or None
IDENTITY_AUDIENCE = os.getenv('IDENTITY_AUDIENCE', '').strip() or None
JWKS_CACHE_TTL = _env_int('JWKS_CACHE_TTL', 900)
JWKS_TIMEOUT = _env_float('JWKS_TIMEOUT', 15)
JWKS_RETRIES = _env_int('JWKS_RETRIES', 2)
# Dev-only: verify HS256 tokens signed with identity-service SECRET_KEY when JWKS is empty.
# Refused in production unless ALLOW_JWT_HS256_FALLBACK is explicitly enabled.
JWT_HS256_FALLBACK_SECRET = os.getenv('JWT_HS256_FALLBACK_SECRET', '').strip() or None
ALLOW_JWT_HS256_FALLBACK = os.getenv('ALLOW_JWT_HS256_FALLBACK', '').strip().lower() in {
    '1',
    'true',
    'yes',
    'on',
}
if JWT_HS256_FALLBACK_SECRET and not DEBUG and not ALLOW_JWT_HS256_FALLBACK:
    raise ImproperlyConfigured(
        'JWT_HS256_FALLBACK_SECRET is set but DEBUG is false. '
        'HS256 fallback must not be enabled in production (forged tokens risk). '
        'Unset JWT_HS256_FALLBACK_SECRET, or set DEBUG=true for local use, '
        'or set ALLOW_JWT_HS256_FALLBACK=true only if you fully understand the risk.'
    )
JWT_ALGORITHMS = _env_csv('JWT_ALGORITHMS', ('RS256',))

# Downstream MCP gateway (aggregated ``POST /mcp``).
MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS = _env_int('MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS', 30)
# discovery: tools/list returns search, describe, and call. all: the full operational catalog.
MCP_TOOLS_LIST_MODE = os.getenv('MCP_TOOLS_LIST_MODE', 'discovery').strip().lower() or 'discovery'
MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS = _env_float('MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS', 5.0)
# Internal approval assertions to identity: must allow longer JWTs during setup (identity #135).
MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS = max(60, _env_int('MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS', 900))
MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS = max(1, _env_int('MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS', 600))
MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS = max(
    MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS,
    _env_int('MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS', 900),
)
# Connected Shellui services (origins only; MCP paths are appended in code).
STORAGE_SERVICE_URL = os.getenv('STORAGE_SERVICE_URL', '').strip().rstrip('/') or None
HOSTING_SERVICE_URL = os.getenv('HOSTING_SERVICE_URL', '').strip().rstrip('/') or None
SAAS_SERVICE_URL = os.getenv('SAAS_SERVICE_URL', '').strip().rstrip('/') or None
# Public origins, the RFC 8707 resource identity mints downstream tokens for ({origin}/mcp).
# Set them when the *_SERVICE_URL above are internal (for example Docker Compose). Unset: same as *_SERVICE_URL.
STORAGE_SERVICE_PUBLIC_URL = os.getenv('STORAGE_SERVICE_PUBLIC_URL', '').strip().rstrip('/') or None
HOSTING_SERVICE_PUBLIC_URL = os.getenv('HOSTING_SERVICE_PUBLIC_URL', '').strip().rstrip('/') or None
EMAIL_SERVICE_PUBLIC_URL = os.getenv('EMAIL_SERVICE_PUBLIC_URL', '').strip().rstrip('/') or None
SAAS_SERVICE_PUBLIC_URL = os.getenv('SAAS_SERVICE_PUBLIC_URL', '').strip().rstrip('/') or None

# RS256 delegation JWTs for identity downstream MCP access-token minting.
from apps.authapi.ai_service_jwks import load_ai_service_signing_key  # noqa: E402


def _load_ai_service_signing_pem() -> str:
    file_path = os.getenv('AI_SERVICE_SIGNING_KEY_FILE', '').strip()
    if file_path:
        path = Path(file_path)
        if not path.is_absolute():
            path = BASE_DIR / path
        if not path.is_file():
            raise ImproperlyConfigured(f'AI_SERVICE_SIGNING_KEY_FILE not found: {path}')
        return path.read_text(encoding='utf-8')
    return os.getenv('AI_SERVICE_SIGNING_KEY', '').strip()


def _default_ai_service_issuer() -> str:
    for origin in CSRF_TRUSTED_ORIGINS:
        origin_str = str(origin).strip().rstrip('/')
        if origin_str.startswith('https://'):
            return origin_str
    return ''


_ai_signing_pem = _load_ai_service_signing_pem()
AI_SERVICE_SIGNING_KID = os.getenv('AI_SERVICE_SIGNING_KID', '').strip()
AI_SERVICE_ISSUER = os.getenv('AI_SERVICE_ISSUER', '').strip().rstrip('/') or _default_ai_service_issuer()
# Public origin of this service. MCP resources are {AI_PUBLIC_URL}/c/<company_id>/mcp.
AI_PUBLIC_URL = os.getenv('AI_PUBLIC_URL', '').strip().rstrip('/') or AI_SERVICE_ISSUER
AI_SERVICE_SIGNING_KEY = (
    load_ai_service_signing_key(private_pem=_ai_signing_pem, kid=AI_SERVICE_SIGNING_KID)
    if _ai_signing_pem
    else None
)

# API auth is Bearer JWT (not cookies). Multi-tenant shells call APIs from
# unknown browser origins, so permissive CORS is intentional when credentials are off
# (Supabase-style). Token delivery stays strict via identity OAuth redirect allowlist.
# Optional lock-down: CORS_ALLOW_ALL_ORIGINS=false + CORS_ALLOWED_ORIGINS.
CORS_ALLOW_ALL_ORIGINS = _env_bool('CORS_ALLOW_ALL_ORIGINS', True)
CORS_ALLOWED_ORIGINS = [
    'http://localhost:4000',
    'http://127.0.0.1:4000',
    'http://localhost:5174',
    'http://127.0.0.1:5174',
    'http://localhost:5175',
    'http://127.0.0.1:5175',
    'https://admin.shellui.com',
]
for _origin in os.getenv('CORS_ALLOWED_ORIGINS', '').split(','):
    _origin = _origin.strip()
    if _origin and _origin not in CORS_ALLOWED_ORIGINS:
        CORS_ALLOWED_ORIGINS.append(_origin)

CORS_ALLOW_CREDENTIALS = _env_bool('CORS_ALLOW_CREDENTIALS', False)

if CORS_ALLOW_ALL_ORIGINS and CORS_ALLOW_CREDENTIALS:
    raise ImproperlyConfigured(
        'CORS_ALLOW_ALL_ORIGINS=true with CORS_ALLOW_CREDENTIALS=true is unsafe — '
        'use explicit CORS_ALLOWED_ORIGINS when credentials are enabled.'
    )
# Public HTTPS origins (admin.shellui.com) calling http://localhost:8001.
# Browsers send Access-Control-Request-Private-Network on the OPTIONS preflight.
CORS_ALLOW_PRIVATE_NETWORK = os.getenv(
    'CORS_ALLOW_PRIVATE_NETWORK', 'true'
).strip().lower() in {'1', 'true', 'yes', 'on'}
CORS_ALLOW_HEADERS = list(
    {
        'accept',
        'accept-encoding',
        'authorization',
        'content-type',
        'dnt',
        'origin',
        'user-agent',
        'x-csrftoken',
        'x-requested-with',
        'x-upsert',
        'x-metadata',
        'cache-control',
        'apikey',
        'x-client-info',
        'x-request-id',
    }
)
CORS_ALLOW_HEADERS.append('mcp-protocol-version')
# Browser MCP clients can read the 401 challenge only when it is exposed.
CORS_EXPOSE_HEADERS = ['X-Request-ID', 'WWW-Authenticate']

# HTTPS / cookie hardening (production defaults; override via env for local HTTP).
SECURE_SSL_REDIRECT = _env_bool('SECURE_SSL_REDIRECT', not DEBUG)
SECURE_HSTS_SECONDS = _env_int('SECURE_HSTS_SECONDS', 31536000 if not DEBUG else 0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = _env_bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', not DEBUG)
SECURE_HSTS_PRELOAD = _env_bool('SECURE_HSTS_PRELOAD', False)
SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', not DEBUG)
CSRF_COOKIE_SECURE = _env_bool('CSRF_COOKIE_SECURE', not DEBUG)
# __Host- names are host-only. Browsers drop them when a Domain attribute is set,
# and they require Secure plus Path=/. Use them only on the secure cookies.
SESSION_COOKIE_NAME = '__Host-sessionid' if SESSION_COOKIE_SECURE else 'sessionid'
CSRF_COOKIE_NAME = '__Host-csrftoken' if CSRF_COOKIE_SECURE else 'csrftoken'
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_DOMAIN = None
CSRF_COOKIE_DOMAIN = None
SESSION_COOKIE_PATH = '/'
CSRF_COOKIE_PATH = '/'

# Django admin exposes cross-tenant data — disable on internet-facing API pods when
# operators use a separate admin ingress with MFA / network restrictions.
DJANGO_ADMIN_ENABLED = _env_bool('DJANGO_ADMIN_ENABLED', True)

# Email notifications. Empty EMAIL_SERVICE_API_KEY disables email MCP in ``list_services``.
# EMAIL_SERVICE_URL is an origin; callers append /api/v1/events.
EMAIL_SERVICE_URL = (
    os.getenv('EMAIL_SERVICE_URL', 'https://email.shellui.com').strip().rstrip('/')
    or 'https://email.shellui.com'
)
EMAIL_SERVICE_API_KEY = os.getenv('EMAIL_SERVICE_API_KEY', '').strip()
# Private and loopback EMAIL_SERVICE_URL values are refused unless this is true.
EMAIL_SERVICE_ALLOW_PRIVATE = _env_bool('EMAIL_SERVICE_ALLOW_PRIVATE', False)
if EMAIL_SERVICE_API_KEY:
    if not EMAIL_SERVICE_API_KEY.startswith('esk_'):
        raise ImproperlyConfigured(
            'EMAIL_SERVICE_API_KEY must be an email-service key with the esk_ prefix.'
        )
    if not EMAIL_SERVICE_URL.startswith(('http://', 'https://')):
        raise ImproperlyConfigured(
            'EMAIL_SERVICE_URL must be an absolute http(s) origin '
            '(no path). '
            f'Got: {EMAIL_SERVICE_URL!r}'
        )

if not DEBUG:
    _production_config_errors = []
    if not IDENTITY_ISSUER:
        _production_config_errors.append(
            'IDENTITY_ISSUER is required when DEBUG=false. '
            'Set to identity-service JWT_ISSUER (identity 0.5.0+), '
            'e.g. https://id.shellui.com.'
        )
    if not IDENTITY_AUDIENCE:
        _production_config_errors.append(
            'IDENTITY_AUDIENCE is required when DEBUG=false. '
            'Set to identity-service JWT_AUDIENCE (identity 0.5.0+), typically shellui.'
        )
    if IDENTITY_JWKS_DOCUMENT is None and not (IDENTITY_JWKS_URL or '').strip():
        _production_config_errors.append(
            'IDENTITY_JWKS, IDENTITY_JWKS_FILE, or IDENTITY_JWKS_URL is required when DEBUG=false. '
            'Pin identity JWKS in production (no runtime fetch-only startup).'
        )
    if not _ai_signing_pem:
        _production_config_errors.append(
            'AI_SERVICE_SIGNING_KEY or AI_SERVICE_SIGNING_KEY_FILE is required when DEBUG=false. '
            'Run: python manage.py generate_signing_key'
        )
    if not AI_SERVICE_SIGNING_KID:
        _production_config_errors.append(
            'AI_SERVICE_SIGNING_KID is required when DEBUG=false (set to the kid from generate_signing_key).'
        )
    if not AI_SERVICE_ISSUER:
        _production_config_errors.append(
            'AI_SERVICE_ISSUER is required when DEBUG=false (this service public https origin).'
        )
    # Length and variety only: the value itself is never printed.
    if (
        len(SECRET_KEY) < 50
        or len(set(SECRET_KEY)) < 5
        or SECRET_KEY.startswith('django-insecure-')
    ):
        _production_config_errors.append(
            'SECRET_KEY is shorter than 50 characters or a placeholder when DEBUG=false. '
            'Generate one with: python manage.py generate_env'
        )
    if _production_config_errors:
        raise ImproperlyConfigured('\n'.join(_production_config_errors))

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'request_id': {
            '()': 'config.request_context.RequestIdFilter',
        },
        'redact_access_secrets': {
            '()': 'config.access_log.RedactAccessLogFilter',
        },
    },
    'formatters': {
        'console': {
            'format': '{asctime} {levelname} [{name}] [req={request_id}] {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'console',
            'filters': ['request_id'],
        },
    },
    'root': {
        'handlers': ['console'],
        'level': LOG_LEVEL,
        'filters': [],
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django.server': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False,
            'filters': [],
        },
        'config': {
            'handlers': ['console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'gunicorn.error': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'gunicorn.access': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
            'filters': ['redact_access_secrets'],
        },
    },
}

SENTRY_DSN = os.getenv('SENTRY_DSN', '').strip()
SENTRY_ENVIRONMENT = os.getenv('SENTRY_ENVIRONMENT', '').strip() or (
    'development' if DEBUG else 'production'
)
SENTRY_RELEASE = os.getenv('SENTRY_RELEASE', '').strip() or VERSION
SENTRY_TRACES_SAMPLE_RATE = _env_float('SENTRY_TRACES_SAMPLE_RATE', 0.0)

if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration

    from config.sentry_scrub import scrub_sentry_event

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(),
            LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
        ],
        environment=SENTRY_ENVIRONMENT,
        release=SENTRY_RELEASE,
        traces_sample_rate=SENTRY_TRACES_SAMPLE_RATE,
        send_default_pii=False,
        include_local_variables=False,
        max_request_body_size='never',
        before_send=scrub_sentry_event,
        attach_stacktrace=True,
    )

# A failing log call must never print its arguments (headers, tokens) to stderr.
logging.raiseExceptions = False
