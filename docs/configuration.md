---
title: Configuration
---

# Configuration

## Required in production (`DEBUG=false`)

| Variable | Notes |
| -------- | ----- |
| `DEBUG` | Must be `false` in production |
| `SECRET_KEY` | Django sessions and CSRF |
| `ALLOWED_HOSTS` | Comma-separated hostnames |
| `CSRF_TRUSTED_ORIGINS` | HTTPS origins for admin |
| `IDENTITY_SERVICE_URL` | identity origin; JWKS at `{url}/.well-known/jwks.json` when not pinned |
| `IDENTITY_ISSUER` | JWT `iss` from identity |
| `IDENTITY_AUDIENCE` | Typically `shellui` |
| `IDENTITY_JWKS` | Pin JWKS JSON in production |
| `IDENTITY_JWKS_FILE` | Or pin JWKS file path |
| `IDENTITY_JWKS_URL` | Fetch URL for dev |
| `REDIS_URL` | Shared cache for MCP gateway |
| `POSTGRES_DATABASE_URL` | Optional; SQLite when empty |
| `AI_SERVICE_SIGNING_KEY` | RSA PEM for RS256 delegation JWTs to identity (or `AI_SERVICE_SIGNING_KEY_FILE`) |
| `AI_SERVICE_SIGNING_KID` | JWKS `kid` (`python manage.py generate_signing_key`) |
| `AI_SERVICE_ISSUER` | JWT `iss` on those requests; defaults to the first `https://` entry in `CSRF_TRUSTED_ORIGINS` |

Identity verifies delegation requests with `AI_SERVICE_JWKS` / `AI_SERVICE_JWKS_URL` (default `{AI_SERVICE_URL}/.well-known/jwks.json`). This service publishes its public key at `GET /.well-known/jwks.json`.

## MCP gateway

| Variable | Default |
| -------- | ------- |
| `MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS` | `30` |
| `MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS` | `5` |
| `MCP_RATE_LIMIT_AGENT` | `120` |

## Downstream services

| Variable | Default |
| -------- | ------- |
| `STORAGE_SERVICE_URL` | empty |
| `HOSTING_SERVICE_URL` | empty |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` |
| `EMAIL_SERVICE_API_KEY` | empty |
| `SAAS_SERVICE_URL` | empty |

## JWKS tuning

| Variable | Default |
| -------- | ------- |
| `JWKS_CACHE_TTL` | `900` |
| `JWKS_TIMEOUT` | `15` |
| `JWKS_RETRIES` | `2` |
| `JWT_ALGORITHMS` | `RS256` |
| `JWT_HS256_FALLBACK_SECRET` | empty |
| `ALLOW_JWT_HS256_FALLBACK` | `false` |

## Docker Compose

| Variable | Default |
| -------- | ------- |
| `AI_SERVICE_PORT` | `8003` |

## Runtime

| Variable | Default |
| -------- | ------- |
| `LOG_LEVEL` | `INFO` |
| `DJANGO_ADMIN_ENABLED` | `true` |
| `SETUP_TOKEN` | empty |
| `SQLITE_PATH` | `db.sqlite3` |
| `POSTGRES_SSL_REQUIRE` | `true` |
| `CORS_ALLOW_ALL_ORIGINS` | `true` |
| `CORS_ALLOW_CREDENTIALS` | `false` |
| `CORS_ALLOWED_ORIGINS` | empty |
| `CORS_ALLOW_PRIVATE_NETWORK` | `true` |
| `SECURE_SSL_REDIRECT` | `true` |
| `SECURE_HSTS_SECONDS` | `31536000` |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `true` |
| `SECURE_HSTS_PRELOAD` | `false` |
| `SESSION_COOKIE_SECURE` | `true` |
| `CSRF_COOKIE_SECURE` | `true` |
| `SENTRY_DSN` | empty |
| `SENTRY_ENVIRONMENT` | `production` |
| `SENTRY_RELEASE` | empty |
| `SENTRY_TRACES_SAMPLE_RATE` | `0` |
| `GUNICORN_WORKERS` | `2` |
| `GUNICORN_THREADS` | `2` |
| `GUNICORN_TIMEOUT` | `120` |
| `GUNICORN_GRACEFUL_TIMEOUT` | `30` |
| `GUNICORN_KEEP_ALIVE` | `75` |
| `GUNICORN_MAX_REQUESTS` | `1000` |
| `GUNICORN_MAX_REQUESTS_JITTER` | `200` |
| `EMAIL_SERVICE_ALLOW_PRIVATE` | `false` |
