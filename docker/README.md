# Docker

`docker-compose.yml` in the repository root runs one ai-service container. `AI_SERVICE_MODE` selects the plane. The default is `region`.

## Region mode (default)

The compose file is a region gateway. It keeps today's `/c/<company_id>/mcp` behavior.

| Variable | Compose default |
| -------- | --------------- |
| `AI_SERVICE_MODE` | `region` |
| `IDENTITY_SERVICE_URL` | `http://host.docker.internal:8001` |
| `IDENTITY_JWKS_URL` | `http://host.docker.internal:8001/.well-known/jwks.json` |
| `IDENTITY_ISSUER` | `http://localhost:8001` |
| `IDENTITY_AUDIENCE` | `shellui` |
| `STORAGE_SERVICE_URL` | `http://host.docker.internal:8002` |
| `HOSTING_SERVICE_URL` | `http://host.docker.internal:8003` |
| `EMAIL_SERVICE_URL` | `http://host.docker.internal:8004` |
| `SAAS_SERVICE_URL` | passed through if set, and ignored. SaaS tools are not on the region gateway. |
| `REDIS_URL` | `redis://redis:6379/5` |
| `AI_SERVICE_PORT` | `8006` |

Do not set `GLOBAL_IDENTITY_URL`, `GLOBAL_OIDC_CLIENT_ID`, `GLOBAL_OIDC_CLIENT_SECRET`, or `SAAS_API_AUDIENCE` on this container. `config/checks.py` refuses that mix.

## Global mode

Run a second container from the same image. Do not point it at regional identity, storage, hosting, or email.

The Shellui dev stack (`shellui/shellui` `dev/docker-compose.yml`, service `ai-global` on port 8008) passes these process env names. Host file names on the left are mapped by Compose. This service reads the process names on the right.

| Host file (`dev/.env.local`) | Process env inside `ai-global` |
| ---------------------------- | ------------------------------ |
| `AI_GLOBAL_SECRET_KEY` | `SECRET_KEY` |
| `AI_GLOBAL_REDIS_URL` (`redis://redis:6379/7`) | `REDIS_URL` |
| `AI_GLOBAL_POSTGRES_DATABASE_URL` (database `ai_global`) | `POSTGRES_DATABASE_URL` |
| `AI_GLOBAL_SERVICE_SIGNING_KEY` | `AI_SERVICE_SIGNING_KEY` |
| `AI_GLOBAL_SERVICE_SIGNING_KID` | `AI_SERVICE_SIGNING_KID` |
| `PUBLIC_AI_GLOBAL_URL` | `AI_SERVICE_ISSUER` and `AI_PUBLIC_URL` |
| `PUBLIC_IDENTITY_GLOBAL_URL` | `GLOBAL_IDENTITY_URL` and `GLOBAL_IDENTITY_ISSUER` |
| `http://identity-global:8000` | `GLOBAL_IDENTITY_INTERNAL_URL` |
| `GLOBAL_JWKS` (identity-global public JWKS) | `GLOBAL_IDENTITY_JWKS` |
| `GLOBAL_OIDC_CLIENT_ID` | `GLOBAL_OIDC_CLIENT_ID` |
| `GLOBAL_OIDC_CLIENT_SECRET` | `GLOBAL_OIDC_CLIENT_SECRET` |
| `{PUBLIC_AI_GLOBAL_URL}/oauth/mcp/signin/complete` | `GLOBAL_OIDC_REDIRECT_URI` |
| `PUBLIC_SAAS_URL` | `SAAS_SERVICE_URL` |
| `http://saas:8000` | `SAAS_SERVICE_INTERNAL_URL` |
| `SAAS_API_AUDIENCE` (`${PUBLIC_SAAS_URL}/api`) | `SAAS_API_AUDIENCE` |
| `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` | `GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` |

`AI_SERVICE_MODE` is the literal `global`. `AI_GLOBAL_JWKS` is not read here. Identity and saas pin that document. This process publishes the same key at `GET /.well-known/jwks.json` from `AI_SERVICE_SIGNING_KEY` and `AI_SERVICE_SIGNING_KID`.

`GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` has no fixed string in code beyond the default `shellui-agents` when the variable is empty. The dev stack sets `shellui_global_agent_dev`, and regional identity and saas use that same value. Production can keep `shellui-agents`.

`GLOBAL_OIDC_CLIENT_ID` is the second confidential client in identity-global `IDENTITY_GLOBAL_OIDC_CLIENTS` (also `OIDC_CLIENTS` on that process). The browser is sent to `{GLOBAL_IDENTITY_URL}/oauth/authorize` with no `prompt=none`. The code is redeemed at `{GLOBAL_IDENTITY_INTERNAL_URL}/oauth/token`.

Unset `IDENTITY_JWKS`, `IDENTITY_JWKS_FILE`, `IDENTITY_JWKS_URL`, `IDENTITY_SERVICE_URL`, `IDENTITY_ISSUER`, `IDENTITY_AUDIENCE`, `STORAGE_SERVICE_URL`, `HOSTING_SERVICE_URL`, and `EMAIL_SERVICE_API_KEY`. The region service `ai` on `:8006` does not set `SAAS_SERVICE_URL`.

This repository's compose file stays a single region container unless you override `AI_SERVICE_MODE`.
