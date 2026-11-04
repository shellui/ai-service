#!/usr/bin/env bash
# One-command MCP client conformance (identity + ai + official SDKs). Local/CI only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${E2E_DIR}/docker-compose.yml"
SECRETS_DIR="${E2E_DIR}/.e2e-secrets"
IDENTITY_SRC="${IDENTITY_SRC:-${ROOT}/../identity-service}"

export AI_SRC="${AI_SRC:-${ROOT}}"
export IDENTITY_SRC
export E2E_IDENTITY_SECRET_KEY="${E2E_IDENTITY_SECRET_KEY:-e2e-identity-secret-not-for-production-0123456789abcdef0123456789ab}"
export E2E_AI_SECRET_KEY="${E2E_AI_SECRET_KEY:-e2e-ai-secret-not-for-production-0123456789abcdef0123456789abcdef}"
export MCP_E2E_COMPOSE_FILE="${COMPOSE_FILE}"
export MCP_URL="${MCP_URL:-http://localhost:8006/c/1/mcp}"
# Must match identity JWT_ISSUER (localhost) so session cookies survive MCP magic-link sign-in.
export IDENTITY_ORIGIN="${IDENTITY_ORIGIN:-http://localhost:8001}"
export E2E_IDENTITY_SECRET_KEY
export MCP_E2E_TOKEN_FILE="${SECRETS_DIR}/access.token"

log() { printf '==> %s\n' "$*"; }

if [[ ! -d "${IDENTITY_SRC}" ]]; then
  echo "IDENTITY_SRC not found at ${IDENTITY_SRC}. Clone shellui/identity-service (develop) alongside ai-service or set IDENTITY_SRC." >&2
  exit 1
fi

mkdir -p "${SECRETS_DIR}"
if [[ ! -f "${SECRETS_DIR}/signing.pem" ]]; then
  log 'Generating ephemeral AI_SERVICE signing key'
  SECRETS_DIR="${SECRETS_DIR}" ROOT="${ROOT}" E2E_AI_SECRET_KEY="${E2E_AI_SECRET_KEY}" \
    uv run --directory "${ROOT}" python - <<'PY'
import os
from pathlib import Path
os.environ.setdefault("SECRET_KEY", os.environ["E2E_AI_SECRET_KEY"])
os.environ.setdefault("DEBUG", "true")
import django
from django.conf import settings
if not settings.configured:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()
from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair
secrets = Path(os.environ["SECRETS_DIR"])
priv, pub = generate_rsa_key_pair()
kid = compute_rsa_kid(pub)
(secrets / "signing.pem").write_text(priv, encoding="utf-8")
(secrets / "signing.kid").write_text(kid, encoding="utf-8")
PY
fi
export E2E_AI_SIGNING_KID="$(cat "${SECRETS_DIR}/signing.kid")"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
}
if [[ "${MCP_E2E_LEAVE_STACK:-}" != "1" ]]; then
  trap cleanup EXIT
fi

log 'Starting MCP e2e stack'
docker compose -f "${COMPOSE_FILE}" build identity ai

IDENTITY_JWT_ENV="${SECRETS_DIR}/identity-jwt.env"
if [[ ! -f "${IDENTITY_JWT_ENV}" ]]; then
  log 'Generating ephemeral identity JWT keys (RS256; MCP revocation assertions)'
  docker compose -f "${COMPOSE_FILE}" run --rm --no-deps --entrypoint python -T identity \
    manage.py generate_jwt_keys --shell | sed 's/^export //' >"${IDENTITY_JWT_ENV}"
fi
export MCP_E2E_IDENTITY_JWT_ENV="${IDENTITY_JWT_ENV}"

docker compose -f "${COMPOSE_FILE}" up -d postgres redis identity ai

log 'Waiting for health checks'
for _ in $(seq 1 60); do
  if curl -sf "${IDENTITY_ORIGIN}/health/live" >/dev/null && curl -sf "http://localhost:8006/ai/v1/health" >/dev/null; then
    break
  fi
  sleep 2
done
curl -sf "${IDENTITY_ORIGIN}/health/live" >/dev/null
curl -sf "http://localhost:8006/ai/v1/health" >/dev/null

log 'Ensuring company 2 exists (tenant isolation)'
docker compose -f "${COMPOSE_FILE}" exec -T identity python manage.py shell <<'PY'
from apps.companies.models import Company
Company.objects.get_or_create(pk=2, defaults={'name': 'E2E Other', 'slug': 'e2e-other', 'enable_magic_link': True})
PY

log 'Installing e2e runner dependencies'
(
  cd "${E2E_DIR}"
  uv sync --frozen 2>/dev/null || uv sync
)
(
  cd "${E2E_DIR}/clients"
  npm ci
)

export MCP_E2E_PYTHON="${E2E_DIR}/.venv/bin/python"

log 'Negative OAuth / MCP checks'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_negatives.py"

log 'OAuth token endpoint (form-urlencoded + refresh)'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_oauth_form.py"

log 'TypeScript MCP SDK client'
node "${E2E_DIR}/clients/run_ts.mjs"

log 'Python MCP SDK client'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_py.py"

log 'MCP tool inputSchema audit (strict client subsets)'
uv run --directory "${ROOT}" python "${E2E_DIR}/clients/run_schema_audit.py"

log 'MCP Inspector CLI (tools/list with OAuth access token)'
INSPECTOR_TOKEN="$(cat "${MCP_E2E_TOKEN_FILE}")"
npx --yes @modelcontextprotocol/inspector --cli \
  --transport http \
  --server-url "${MCP_URL}" \
  --header "Authorization: Bearer ${INSPECTOR_TOKEN}" \
  --header "Accept: application/json, text/event-stream" \
  --method tools/list

log 'Revoked agent token rejected'
docker compose -f "${COMPOSE_FILE}" exec -T identity python manage.py shell <<'PY'
from django.utils import timezone
from apps.agents.models import Agent
Agent.objects.filter(company_id=1).update(revoked_at=timezone.now())
PY
docker compose -f "${COMPOSE_FILE}" exec -T ai python manage.py shell <<'PY'
from django.core.cache import cache
from apps.connector.mcp_identity import _refresh_revocations
cache.delete('mcp:revoked_trusted_payload')
cache.delete('mcp:revoked_list_trusted')
if not _refresh_revocations():
    raise SystemExit('revocation poll failed after agent revoke (check identity /api/v1/mcp/internal/mcp-revocations)')
PY
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${MCP_URL}" \
  -H "Authorization: Bearer ${INSPECTOR_TOKEN}" \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')"
if [[ "${code}" != "403" ]]; then
  echo "expected HTTP 403 for revoked agent, got ${code}" >&2
  exit 1
fi
echo '[inspector] tools/list with bearer token: ok'
echo '[revoked] agent token rejected after revoke: ok'

log 'All MCP client conformance checks passed'
