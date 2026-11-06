---
title: Configuration
---

# Configuration

For the Shellui multi-service stack (`shellui/shellui/dev`), see [Local dev stack](./devstack.md) for compose service name **`ai`**, host port **8006**, internal URLs (`http://identity:8000`, …), and public issuers (`http://localhost:8001`, `http://localhost:8006`).

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
| `AI_PUBLIC_URL` | Public origin of the gateway; the MCP resource is `{AI_PUBLIC_URL}/c/<company_id>/mcp`. Defaults to `AI_SERVICE_ISSUER` |

Identity verifies delegation requests with `AI_SERVICE_JWKS` / `AI_SERVICE_JWKS_URL` (default `{AI_SERVICE_URL}/.well-known/jwks.json`). This service publishes its public key at `GET /.well-known/jwks.json`.

## MCP gateway

| Variable | Default |
| -------- | ------- |
| `MCP_GATEWAY_TOOLS_CACHE_TTL_SECONDS` | `30` |
| `MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS` | `5` |
| `MCP_RATE_LIMIT_AGENT` | `120` |
| `MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS` | `900` | Maximum `exp - iat` for RS256 approval assertions to identity (setup flows need 600–900s; align with identity `MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS`). |
| `MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS` | `600` | Lower bound for signed `mcp_session_ttl_seconds` during setup (must match identity). |
| `MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS` | `900` | Upper bound for the same. |
| `MCP_SESSION_GRANT_INDEX_MAX_SECONDS` | `3600` | Max Django cache entry TTL for per-connection session-grant bookkeeping (used to invalidate all grants for an agent/company on revoke). |
| `MCP_SETUP_REQUIRES_ABSOLUTE_EXPIRY` | `false` | When `true`, `setup_flow` assertions require `setup_expires_at` on the verified regional access token (enable after identity #135). |
| `MCP_SESSION_GRANT_REQUIRES_ABSOLUTE_EXPIRES_AT` | `false` | When `true`, setup-mode session grants are rejected unless session-check returns an absolute `expires_at` (or a setup cap applies); use after identity #135. |

## Downstream services

| Variable | Default |
| -------- | ------- |
| `STORAGE_SERVICE_URL` | empty |
| `HOSTING_SERVICE_URL` | empty |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` |
| `EMAIL_SERVICE_API_KEY` | empty |
| `SAAS_SERVICE_URL` | empty |
| `STORAGE_SERVICE_PUBLIC_URL` | same as `STORAGE_SERVICE_URL` |
| `HOSTING_SERVICE_PUBLIC_URL` | same as `HOSTING_SERVICE_URL` |
| `EMAIL_SERVICE_PUBLIC_URL` | same as `EMAIL_SERVICE_URL` |
| `SAAS_SERVICE_PUBLIC_URL` | same as `SAAS_SERVICE_URL` |

The gateway calls each service at `{*_SERVICE_URL}/mcp`, and asks identity for a token bound to the public resource `{*_SERVICE_PUBLIC_URL}/mcp` (identity uses `IDENTITY_ISSUER`). Identity only mints tokens for resources in its catalog, so set the public URLs whenever the service URLs are internal. A URL that is not configured never gets a token.

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
| `AI_SERVICE_PORT` | `8006` |

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
