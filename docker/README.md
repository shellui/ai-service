# Run the Shellui MCP gateway

ai-service is the per-company Model Context Protocol (MCP) gateway in Shellui. A client calls `POST /c/<company_id>/mcp` for one company. The gateway calls tools on identity, storage, hosting, email, and SaaS. Destructive tool calls require approval before they run.

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

Set the required variables, then start `shellui/ai-service:latest`. `SECRET_KEY` must be at least 50 characters. `AI_SERVICE_SIGNING_KEY` must be an RSA private key in PEM form. Replace the placeholder hosts and secrets before you start the server.

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

## Required environment variables

Set these for a production container. `config/env_registry.py` marks each name required. When `DEBUG` is `false`, startup also requires a JSON Web Key Set (JWKS) document, file, or URL.

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

- **`X.Y.Z`**: semver without the leading `v` (`v0.1.0` becomes `0.1.0`)
- **`X.Y`**: major and minor (`0.1`)
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
