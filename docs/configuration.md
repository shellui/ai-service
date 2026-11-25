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
| `IDENTITY_ISSUER` | JWT `iss` from identity. Protected-resource `authorization_servers` is this value (Identity metadata `issuer`), not `IDENTITY_SERVICE_URL` when the two differ |
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
| `MCP_TOOLS_LIST_MODE` | `discovery`. `discovery` returns the short search catalog. `all` returns every operational tool. |
| `MCP_GATEWAY_DOWNSTREAM_TIMEOUT_SECONDS` | `5` |
| `MCP_RATE_LIMIT_AGENT` | `120` |
| `MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS` | `900` | Maximum `exp - iat` for RS256 approval assertions to identity (setup flows need 600–900s; align with identity `MCP_APPROVAL_ASSERTION_MAX_LIFETIME_SECONDS`). |
| `MCP_APPROVAL_SETUP_SESSION_TTL_MIN_SECONDS` | `600` | Lower bound for signed `mcp_session_ttl_seconds` during setup (must match identity). |
| `MCP_APPROVAL_SETUP_SESSION_TTL_MAX_SECONDS` | `900` | Upper bound for the same. |
| `MCP_APPROVAL_CHANNEL_BY_COMPANY` | empty | JSON map of company id to `form` or `link` for non-destructive tools. Destructive tools always use the approval link. Example: `{"10": "link"}`. |
| `MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS` | `90` | Seconds `ai_get_approval` SSE waits for an approval decide wake. Keep this under `GUNICORN_TIMEOUT` (default 120). |
| `MCP_CALL_LOG_RETENTION_DAYS` | `90` | Days to keep gateway MCP tool-call logs. `python manage.py prune_mcp_call_logs` deletes older rows. |

`setup_flow` assertions and session grants always require absolute `setup_expires_at` (token + session-check response when setup) and absolute `expires_at` on the session-check response; there are no toggles.

## Downstream services

| Variable | Default |
| -------- | ------- |
| `STORAGE_SERVICE_URL` | empty |
| `HOSTING_SERVICE_URL` | empty |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` |
| `EMAIL_SERVICE_API_KEY` | empty |
| `SAAS_SERVICE_URL` | empty. Ignored when `AI_SERVICE_MODE=region`. Required for global mode. |
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

## Mode

`AI_SERVICE_MODE` is `region` (default) or `global`. One image, one codebase, chosen at boot. Region mode serves `/c/<company_id>/mcp` and does not serve the global authorization server. Global mode serves `https://ai.shellui.com/mcp` (no company in the path) and does not serve `/c/<company_id>/mcp`.

`config/checks.py` refuses a mix. Global mode must not set `IDENTITY_JWKS`, `IDENTITY_JWKS_FILE`, `IDENTITY_JWKS_URL`, `IDENTITY_SERVICE_URL`, `IDENTITY_ISSUER`, `IDENTITY_AUDIENCE`, `STORAGE_SERVICE_URL`, `HOSTING_SERVICE_URL`, or `EMAIL_SERVICE_API_KEY`. Region mode must not set `GLOBAL_IDENTITY_URL`, `GLOBAL_OIDC_CLIENT_ID`, `GLOBAL_OIDC_CLIENT_SECRET`, or `SAAS_API_AUDIENCE`.

### Global mode

Required when `DEBUG=false` and `AI_SERVICE_MODE=global`: `GLOBAL_IDENTITY_URL`, `GLOBAL_IDENTITY_ISSUER`, `GLOBAL_IDENTITY_JWKS` or `GLOBAL_IDENTITY_JWKS_URL`, `GLOBAL_OIDC_CLIENT_ID`, `GLOBAL_OIDC_CLIENT_SECRET`, `GLOBAL_OIDC_REDIRECT_URI`, `SAAS_SERVICE_URL`, `SAAS_API_AUDIENCE`, plus the shared signing key and `AI_SERVICE_ISSUER`. Regional identity settings are not required and must be unset.

| Variable | Default |
| -------- | ------- |
| `AI_SERVICE_MODE` | `region` |
| `GLOBAL_IDENTITY_URL` | empty. Public identity-global origin. The browser is sent to `{url}/oauth/authorize`. |
| `GLOBAL_IDENTITY_INTERNAL_URL` | `GLOBAL_IDENTITY_URL`. Token and userinfo calls. |
| `GLOBAL_REGION_INTERNAL_URLS` | empty. Comma list of `public=internal` origins for server-side calls to regions (token exchange and regional MCP), for example `https://id.eu.shellui.com=http://identity-eu:8000,https://ai.eu.shellui.com=http://ai-eu:8000`. The MCP `resource` and token audiences keep the public URL. |
| `GLOBAL_IDENTITY_ISSUER` | empty |
| `GLOBAL_IDENTITY_AUDIENCE` | `shellui`. `aud` of identity-global access tokens used by the dashboard connections API (identity-global `JWT_AUDIENCE`). |
| `GLOBAL_IDENTITY_JWKS` | empty. Pinned identity-global JWKS JSON. One pair of wrapping quotes is ignored, so a Compose env file can quote the document. The dev stack copies host `GLOBAL_JWKS` into this name. |
| `GLOBAL_IDENTITY_JWKS_URL` | `{GLOBAL_IDENTITY_URL}/.well-known/jwks.json` when the URL is set |
| `GLOBAL_OIDC_CLIENT_ID` | empty |
| `GLOBAL_OIDC_CLIENT_SECRET` | empty |
| `GLOBAL_OIDC_REDIRECT_URI` | empty. Production value `https://ai.shellui.com/oauth/mcp/signin/complete` |
| `SAAS_SERVICE_INTERNAL_URL` | empty. Falls back to `SAAS_SERVICE_URL` for server-side REST. |
| `SAAS_API_AUDIENCE` | empty. `aud` on saas API tokens, typically `https://saas.shellui.com/api` |
| `GLOBAL_MCP_ACCESS_TOKEN_TTL_SECONDS` | `3600` |
| `GLOBAL_MCP_REFRESH_TOKEN_TTL_SECONDS` | `2592000` (30 days, rotating) |
| `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` | `shellui-agents` when unset. The dev stack sets `shellui_global_agent_dev` so ai-global, saas, and regional identity share one `aud`. |
| `MCP_APPROVAL_SESSION_TTL_SECONDS` | `60` |
| `MCP_SETUP_APPROVAL_SESSION_TTL_SECONDS` | `900` |
| `MCP_DYNAMIC_CLIENT_REGISTRATION` | `true` |
| `GLOBAL_COMPANY_WAIT_SECONDS` | `60` |
| `GLOBAL_COMPANY_POLL_SECONDS` | `2` |

Shared by both modes: `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `AI_PUBLIC_URL`, `AI_SERVICE_ISSUER`, `AI_SERVICE_SIGNING_KEY` (or `AI_SERVICE_SIGNING_KEY_FILE`), `AI_SERVICE_SIGNING_KID`, `REDIS_URL`, `POSTGRES_DATABASE_URL`, `MCP_TOOLS_LIST_MODE`.

Global MCP access tokens use `aud` `{AI_PUBLIC_URL}/mcp`. SaaS API tokens use `aud` `SAAS_API_AUDIENCE` and `token_type` `saas_api`. Subject tokens for regional exchange use `aud` `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` (`shellui-agents`), `token_type` `agent_access`, and `mcp_authority` `global_delegated`. All three are signed with `AI_SERVICE_SIGNING_KEY`. The public key is `GET /.well-known/jwks.json`.

## OpenTelemetry

Export stays off until `OTEL_EXPORTER_OTLP_ENDPOINT` is set. With an endpoint, the process sends traces and metrics over OTLP HTTP using protobuf. `OTEL_SDK_DISABLED=true` leaves export off even when an endpoint is set. Do not wrap the process with `opentelemetry-instrument`. Gunicorn `gthread` workers are fork-safe.

WSGI (`config.wsgi`) and ASGI (`config.asgi`) call setup before serving. This service has no Celery app and no long-running management command.

| Variable | Default |
| -------- | ------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | empty. Example: `https://signoz.example:4318` |
| `OTEL_EXPORTER_OTLP_HEADERS` | empty. Exporter headers, including SigNoz basic auth (`Authorization=Basic%20...`). |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` |
| `OTEL_SERVICE_NAME` | `ai-service` |
| `OTEL_RESOURCE_ATTRIBUTES` | empty. Set `deployment.environment` and `cloud.region` here, for example `deployment.environment=production,cloud.region=eu`. |

The process adds `shellui.mode` (`region` or `global`, from `AI_SERVICE_MODE`) unless `OTEL_RESOURCE_ATTRIBUTES` already sets that key. `service.version` is the package version. `SENTRY_ENVIRONMENT` is sent as `deployment.environment` when `OTEL_RESOURCE_ATTRIBUTES` does not set it.

Logs include `trace_id` and `span_id` next to the existing request id. An MCP span records `mcp.method.name` and, for `tools/call`, `mcp.tool.name`. Arguments and results stay off the span. Downstream `requests` calls carry W3C `traceparent`, including the gateway hop and identity token minting.

`GET /metrics` and `GET /metrics/all` are not served.

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
