# Run the Shellui MCP gateway

ai-service is the Model Context Protocol (MCP) gateway in Shellui. One image runs in region mode or global mode. `AI_SERVICE_MODE` chooses the plane at boot. The default is `region`.

Region mode serves `POST /c/<company_id>/mcp` for one company. The gateway calls tools on identity, storage, hosting, and email. SaaS tools are not on this plane. Destructive tool calls require approval before they run.

Global mode serves `POST /mcp` with no company in the path. Run it as a second container. It does not call regional identity, storage, hosting, or email.

## What the image contains

Docker Hub publishes the production stage for `linux/amd64` and `linux/arm64`. The image contains:

- **Base image**: `python:3.14-slim`
- **Listen port**: `8000`
- **Entrypoint**: `/app/tools/docker-entrypoint.sh`
- **Default mode**: `web` (migrate, deploy check, then gunicorn)
- **Server user**: `appuser`
- **Data volume**: `/app/data`

The entrypoint starts as root, prepares `/app/data`, then runs gunicorn as `appuser`. Leave `POSTGRES_DATABASE_URL` empty to store SQLite in that volume.

## Run a container

The commands below start region mode. Set the required variables, then start `shellui/ai-service:latest`. `SECRET_KEY` must be at least 50 characters. `AI_SERVICE_SIGNING_KEY` must be an RSA private key in PEM form. Replace the placeholder hosts and secrets before you start the server.

This command prints a fresh `SECRET_KEY`, a signing key, and the other required names. It does not start the server. Copy the secret and the signing key into the next command, and store the output in a secret manager:

```bash
docker run --rm --entrypoint python \
  shellui/ai-service:latest \
  manage.py generate_env --host ai.example.com
```

`docker run` publishes port 8000 and stores SQLite in a named volume. Point `REDIS_URL` at a Redis server that is already running:

```bash
docker run -d --name ai-service \
  --publish 8000:8000 \
  --volume ai-service-data:/app/data \
  --env SECRET_KEY=your_secret_key_here_012345678901234567890123456789 \
  --env DEBUG=false \
  --env ALLOWED_HOSTS=ai.example.com \
  --env CSRF_TRUSTED_ORIGINS=https://ai.example.com \
  --env IDENTITY_SERVICE_URL=https://id.example.com \
  --env IDENTITY_ISSUER=https://id.example.com \
  --env IDENTITY_AUDIENCE=shellui \
  --env IDENTITY_JWKS_URL=https://id.example.com/.well-known/jwks.json \
  --env REDIS_URL=redis://your_redis_host_here:6379/0 \
  --env POSTGRES_DATABASE_URL= \
  --env AI_SERVICE_SIGNING_KEY=your_signing_key_here \
  --env AI_SERVICE_SIGNING_KID=your_signing_kid_here \
  --env AI_SERVICE_ISSUER=https://ai.example.com \
  shellui/ai-service:latest
```

This Compose file starts Redis on the same network and passes the same settings. The Redis hostname in `REDIS_URL` is the service name:

```yaml
services:
  redis:
    image: redis:8-alpine
  ai-service:
    image: shellui/ai-service:latest
    ports:
      - "8000:8000"
    volumes:
      - ai-service-data:/app/data
    environment:
      SECRET_KEY: your_secret_key_here_012345678901234567890123456789
      DEBUG: "false"
      ALLOWED_HOSTS: ai.example.com
      CSRF_TRUSTED_ORIGINS: https://ai.example.com
      IDENTITY_SERVICE_URL: https://id.example.com
      IDENTITY_ISSUER: https://id.example.com
      IDENTITY_AUDIENCE: shellui
      IDENTITY_JWKS_URL: https://id.example.com/.well-known/jwks.json
      REDIS_URL: redis://redis:6379/0
      POSTGRES_DATABASE_URL: ""
      AI_SERVICE_SIGNING_KEY: your_signing_key_here
      AI_SERVICE_SIGNING_KID: your_signing_kid_here
      AI_SERVICE_ISSUER: https://ai.example.com
volumes:
  ai-service-data:
```

## Region mode (default)

`docker-compose.yml` in the repository root runs one ai-service container as a region gateway. It serves `/c/<company_id>/mcp`.

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

With `DEBUG=false`, global mode requires `GLOBAL_IDENTITY_URL`, `GLOBAL_IDENTITY_ISSUER`, `GLOBAL_IDENTITY_JWKS` or `GLOBAL_IDENTITY_JWKS_URL`, `GLOBAL_OIDC_CLIENT_ID`, `GLOBAL_OIDC_CLIENT_SECRET`, `GLOBAL_OIDC_REDIRECT_URI`, `SAAS_SERVICE_URL`, and `SAAS_API_AUDIENCE`, plus the shared signing key and `AI_SERVICE_ISSUER`. Leave `IDENTITY_JWKS`, `IDENTITY_JWKS_FILE`, `IDENTITY_JWKS_URL`, `IDENTITY_SERVICE_URL`, `IDENTITY_ISSUER`, `IDENTITY_AUDIENCE`, `STORAGE_SERVICE_URL`, `HOSTING_SERVICE_URL`, and `EMAIL_SERVICE_API_KEY` unset.

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

`GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE` defaults to `shellui-agents` when the variable is empty. The dev stack sets `shellui_global_agent_dev`, and regional identity and saas use that same value. Production can keep `shellui-agents`.

`GLOBAL_OIDC_CLIENT_ID` is the second confidential client in identity-global `IDENTITY_GLOBAL_OIDC_CLIENTS` (also `OIDC_CLIENTS` on that process). The browser is sent to `{GLOBAL_IDENTITY_URL}/oauth/authorize` with no `prompt=none`. The code is redeemed at `{GLOBAL_IDENTITY_INTERNAL_URL}/oauth/token`.

The region service `ai` on `:8006` does not set `SAAS_SERVICE_URL`. This repository's compose file stays a single region container unless you override `AI_SERVICE_MODE`.

## Required environment variables

Set these for a production region container. `config/env_registry.py` marks each name required. When `DEBUG` is `false`, startup also requires a JSON Web Key Set (JWKS) document, file, or URL.

| Variable | What to set |
| --- | --- |
| `SECRET_KEY` | Signs sessions, at least 50 characters |
| `DEBUG` | `false` in production (the image default) |
| `ALLOWED_HOSTS` | Comma-separated host names, no scheme |
| `CSRF_TRUSTED_ORIGINS` | Full HTTPS origin of this service |
| `IDENTITY_SERVICE_URL` | identity-service origin |
| `IDENTITY_ISSUER` | JSON Web Token (JWT) issuer, same value as identity-service `JWT_ISSUER` |
| `IDENTITY_AUDIENCE` | Same value as identity-service `JWT_AUDIENCE` |
| `IDENTITY_JWKS_URL` | JWKS URL, or set `IDENTITY_JWKS` or `IDENTITY_JWKS_FILE` instead |
| `REDIS_URL` | Redis URL for the tool catalog cache and rate limits |
| `POSTGRES_DATABASE_URL` | PostgreSQL connection string, or empty for SQLite on `/app/data` |
| `AI_SERVICE_SIGNING_KEY` | RSA private key in PEM form, or set `AI_SERVICE_SIGNING_KEY_FILE` |
| `AI_SERVICE_SIGNING_KID` | Key id from `generate_signing_key` or `generate_env` |
| `AI_SERVICE_ISSUER` | Public HTTPS origin of this gateway |

Optional settings and downstream URLs are in the [configuration reference](https://github.com/shellui/ai-service/blob/main/docs/configuration.md).

## Image tags

`.github/workflows/publish.yml` pushes these tags for a stable release:

- **`X.Y.Z`**: semver without the leading `v` (`v0.2.0` becomes `0.2.0`)
- **`X.Y`**: major and minor (`0.2`)
- **`latest`**: this tag is the highest stable semver

A pre-release does not move `latest`. Commands on this page use `latest`.

## Health check

The image requests `GET /health/live` on port 8000 every 30s. The response body is `ok`. The check does not query the database or Redis. `GET /ai/v1/health` returns JSON with `status`, `service`, and `version`.

## Project links

This repository includes the MIT License:

- **Source**: [ai-service on GitHub](https://github.com/shellui/ai-service)
- **Docs**: [Shellui docs](https://docs.shellui.com)
- **Changelog**: [CHANGELOG.md](https://github.com/shellui/ai-service/blob/main/CHANGELOG.md)
- **License**: [MIT License](https://github.com/shellui/ai-service/blob/main/LICENSE)
- **Shellui**: [shellui.com](https://shellui.com)
