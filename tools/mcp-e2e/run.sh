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

# Redact credentials before failure logs are printed. JWTs, PEM blocks, and
# assignment-style secrets must not land in CI output.
redact_stream() {
  python3 -c '
import re, sys
text = sys.stdin.read()
text = re.sub(
    r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----",
    "[REDACTED_PEM]",
    text,
)
text = re.sub(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    "[REDACTED_JWT]",
    text,
)
text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1[REDACTED]", text)
text = re.sub(
    r"(?i)((?:password|secret|token|authorization|api[_-]?key|private[_-]?key|jwt_private_key|signing_key)(\s*[:=]\s*|\s+))([^\s\"'"'"']+)",
    lambda m: m.group(1) + "[REDACTED]",
    text,
)
sys.stdout.write(text)
'
}

dump_failure_logs() {
  local dest="${MCP_E2E_FAILURE_LOG:-/tmp/mcp-e2e-failure.log}"
  {
    printf '==> docker compose logs ai identity saas-mock (redacted)\n'
    docker compose -f "${COMPOSE_FILE}" logs --no-color ai identity saas-mock 2>&1 || true
  } | redact_stream | tee "${dest}" >&2 || true
}

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

on_exit() {
  local code=$?
  if [[ "${code}" -ne 0 ]]; then
    dump_failure_logs
  fi
  if [[ "${MCP_E2E_LEAVE_STACK:-}" != "1" ]]; then
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "${code}"
}
trap on_exit EXIT

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

log 'Revocation body echoes signed max_active_grant_version'
docker compose -f "${COMPOSE_FILE}" exec -T ai python manage.py shell <<'PY'
from apps.connector import mcp_identity
import requests
origin = mcp_identity._identity_origin()
url = f"{origin}/api/v1/mcp/internal/mcp-revocations"
response = requests.get(url, headers=mcp_identity._revocation_headers(origin), timeout=5)
body = response.json()
if "max_active_grant_version" not in body or isinstance(body.get("max_active_grant_version"), bool):
    raise SystemExit(
        "revocation JSON omitted max_active_grant_version "
        f"(HTTP {response.status_code}, keys={sorted(k for k in body if k != 'revocation_assertion')})"
    )
try:
    trusted = mcp_identity.verify_mcp_revocation_list_response(
        body, **mcp_identity._revocation_verify_kwargs(origin)
    )
except Exception as exc:
    raise SystemExit(f"revocation verify failed: {type(exc).__name__}: {exc}") from exc
if trusted.get("max_active_grant_version") != body["max_active_grant_version"]:
    raise SystemExit("revocation max_active_grant_version body does not match the signed claim")
print("[revocation] max_active_grant_version echoed and verified")
PY

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

log 'SaaS OAuth hint + personal agent tokens'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_personal_saas.py"

log 'Negative OAuth / MCP checks'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_negatives.py"

log 'OAuth token endpoint (form-urlencoded + refresh)'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_oauth_form.py"

log 'OAuth device login (RFC 8628)'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_device_flow.py"

log 'TypeScript MCP SDK client'
node "${E2E_DIR}/clients/run_ts.mjs"

log 'Python MCP SDK client'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_py.py"

log 'Tool titles and annotations (live tools/list)'
"${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_tool_metadata.py"

log 'MCP tool inputSchema audit (strict client subsets)'
PYTHONPATH="${ROOT}" "${MCP_E2E_PYTHON}" "${E2E_DIR}/clients/run_schema_audit.py"

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
