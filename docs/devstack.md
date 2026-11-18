---
title: Shellui local dev stack
---

# Shellui local dev stack

The full multi-service stack lives in **shellui/shellui** at `dev/docker-compose.yml`. Clone this repo next to the other Shellui services and start everything from shellui:

```bash
cd shellui/dev
./start.sh
```

Clone layout, URLs, common commands and troubleshooting are in the [Shellui dev stack guide](https://github.com/shellui/shellui/blob/develop/docs/dev-stack.md). This page only covers what is specific to this service.

This service image must be built with Docker target **`dev`** (deps in `/opt/venv`, source bind-mounted at `/app`). Browser URL: `http://localhost:8006`. Compose service name (internal DNS): **`ai`**.

## Environment variables

Set these on the **`ai`** container (shellui `dev/.env.local.example` may prefix names with `AI_` to avoid clashes; compose maps them to the names below).

| Variable | Local stack value | Notes |
| -------- | ----------------- | ----- |
| `SECRET_KEY` | generated | Django sessions and CSRF. At least 50 characters in production. |
| `DEBUG` | `true` | Enables runserver autoreload and relaxed signing checks. |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,ai` | Include compose service name for internal health checks. |
| `CSRF_TRUSTED_ORIGINS` | `http://localhost:8006,http://127.0.0.1:8006` | Add admin, dashboard, and files origins if you use Django admin locally. |
| `POSTGRES_DATABASE_URL` | `postgres://<user>:<pass>@postgres:5432/ai` | Shared Postgres; database name `ai`. Empty uses SQLite under `/app/data`. |
| `REDIS_URL` | `redis://redis:6379/5` | Shared Redis; DB index `5` for ai-service. |
| `IDENTITY_ISSUER` | `http://localhost:8001` | Public JWT `iss` (identity host port). |
| `IDENTITY_AUDIENCE` | `shellui` | Must match identity-service `JWT_AUDIENCE`. |
| `IDENTITY_JWKS_URL` | `http://identity:8000/.well-known/jwks.json` | Internal JWKS fetch (server-to-server). |
| `IDENTITY_SERVICE_URL` | `http://identity:8000` | Internal origin for identity MCP (`/mcp`). |
| `AI_SERVICE_ISSUER` | `http://localhost:8006` | Public `iss` on RS256 delegation JWTs to identity. |
| `AI_PUBLIC_URL` | `http://localhost:8006` | Public origin; the MCP URL is `{url}/c/<company_id>/mcp`. Defaults to `AI_SERVICE_ISSUER`. |
| `AI_SERVICE_SIGNING_KEY` | PEM or empty | RS256 private key; prefer `AI_SERVICE_SIGNING_KEY_FILE` on a mounted volume. |
| `AI_SERVICE_SIGNING_KEY_FILE` | `/app/data/signing.pem` | Run `python manage.py generate_signing_key` once and persist under `/app/data`. |
| `AI_SERVICE_SIGNING_KID` | from `generate_signing_key` | Required when `DEBUG=false`; recommended in the stack. |
| `STORAGE_SERVICE_URL` | `http://storage:8000` | Downstream MCP origin. |
| `HOSTING_SERVICE_URL` | `http://hosting:8000` | Downstream MCP origin. |
| `EMAIL_SERVICE_URL` | `http://email:8000` | Downstream MCP origin. |
| `EMAIL_SERVICE_ALLOW_PRIVATE` | `true` | Allows internal `http://` email origin in the stack. |
| `EMAIL_SERVICE_API_KEY` | `esk_…` or empty | Empty omits email from the aggregated MCP catalog. |
| `SAAS_SERVICE_URL` | `http://saas:8000` | Downstream MCP origin. |
| `STORAGE_SERVICE_PUBLIC_URL` | `http://localhost:8002` | Public resource for downstream tokens (`{url}/mcp`). |
| `HOSTING_SERVICE_PUBLIC_URL` | `http://localhost:8003` | Same, for hosting. |
| `EMAIL_SERVICE_PUBLIC_URL` | `http://localhost:8004` | Same, for email. |
| `SAAS_SERVICE_PUBLIC_URL` | `http://localhost:8005` | Same, for saas. |
| `SECURE_SSL_REDIRECT` | `false` | Local HTTP. |
| `SESSION_COOKIE_SECURE` | `false` | Local HTTP. |
| `CSRF_COOKIE_SECURE` | `false` | Local HTTP. |

Optional tuning (defaults in [Configuration](./configuration.md)): `MCP_GATEWAY_*`, `JWKS_*`, `CORS_*`, `LOG_LEVEL`, `JWT_HS256_FALLBACK_SECRET` (dev only).

## This repo only

To run ai-service with its root `docker-compose.yml` (Redis plus bind-mounted source):

```bash
cp .env.example .env
# set SECRET_KEY; run: python manage.py generate_signing_key >> .env (or mount AI_SERVICE_SIGNING_KEY_FILE)
docker compose up --build
```

Health: `GET http://localhost:8006/ai/v1/health`

MCP: `POST http://localhost:8006/c/<company_id>/mcp`. Headless clients connect with OAuth device login against Identity (`http://localhost:8001`) and this gateway (`http://localhost:8006`). See [Device login](./mcp-device-login.md). Do not paste an access token into the agent chat.

Sibling services on the host use `host.docker.internal` defaults in `docker-compose.yml`; inside the shellui stack use the internal URLs in the table above.
