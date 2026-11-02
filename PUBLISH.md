# Publish and deploy

How to build, publish, and run the `shellui/ai-service` Docker image on Docker Hub (`hub.docker.com/r/shellui/ai-service`).

Publishing is automatic: publishing a GitHub release builds and pushes the image.

## Image overview

| Item        | Value                                                       |
| ----------- | ----------------------------------------------------------- |
| Registry    | Docker Hub                                                  |
| Repository  | `shellui/ai-service`                                        |
| Listen port | `8000` (Compose maps host `${AI_SERVICE_PORT:-8003}`)       |
| Data volume | `/app/data` (SQLite when not using Postgres)                |

## Pre-release checklist

```bash
./tools/pre-release-check.sh
```

| Step | What it verifies |
|------|------------------|
| Version alignment | `pyproject.toml`, dated `CHANGELOG.md` entry, `uv.lock` |
| Build secrets | No `.env` in image or git |
| Image smoke test | Redis + `GET /ai/v1/health` returns `status=ok` |

GitHub Actions: [`.github/workflows/pre-release.yml`](.github/workflows/pre-release.yml) on pull requests to `main`.

## Publish to Docker Hub

### Automatic publish (GitHub Actions)

[`.github/workflows/publish.yml`](.github/workflows/publish.yml)

- **Trigger:** GitHub release published, or **workflow_dispatch** with tag `vX.Y.Z`.
- **Build:** buildx multi-arch `linux/amd64`, `linux/arm64`.
- **Tags:** semver `X.Y.Z`, `X.Y`, and `latest` when this tag is the highest stable semver in the repo. Pre-releases never move `latest`.

Required GitHub secrets (organization secrets shared with service repos):

| Secret               | Value |
| -------------------- | ----- |
| `DOCKERHUB_USERNAME` | `shellui` |
| `DOCKERHUB_TOKEN`    | Docker Hub access token with push to `shellui/ai-service` and pull for base images |

Required Docker Hub repository: **`shellui/ai-service`** on Docker Hub under the `shellui` organization (create empty repo if missing; CI pushes on release).

**Health check:** Docker `HEALTHCHECK` calls `GET /health/live` on port `8000` (`tools/healthcheck.py`).

### Manual publish (fallback)

```bash
VERSION=0.1.0
IMAGE=shellui/ai-service
docker buildx build --platform linux/amd64,linux/arm64 \
  -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" --push .
```

## Deploy

```bash
docker run -d --name ai-service -p 8003:8000 \
  -e SECRET_KEY='…' \
  -e REDIS_URL='redis://redis:6379/0' \
  -e IDENTITY_JWKS='{"keys":[…]}' \
  -e IDENTITY_ISSUER='https://id.shellui.com' \
  -e IDENTITY_AUDIENCE='shellui' \
  -e IDENTITY_SERVICE_URL='https://id.shellui.com' \
  -e AI_SERVICE_SIGNING_KEY='…' \
  -e AI_SERVICE_SIGNING_KID='…' \
  -e AI_SERVICE_ISSUER='https://ai.shellui.com' \
  -e CSRF_TRUSTED_ORIGINS='https://ai.shellui.com' \
  -e STORAGE_SERVICE_URL='https://storage.shellui.com' \
  shellui/ai-service:0.1.0
```

Generate signing material before deploy:

```bash
uv run python manage.py generate_signing_key
```

See [docs/configuration.md](docs/configuration.md) and `.env.example`.
