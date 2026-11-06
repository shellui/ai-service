---
title: MCP client conformance (e2e)
---

# MCP client conformance (e2e)

This suite proves the Shellui MCP gateway works with **official MCP clients**, not ai-service test doubles:

- `@modelcontextprotocol/sdk` (TypeScript) with OAuth protected-resource discovery, dynamic client registration, PKCE S256, magic-link sign-in, token exchange, refresh, `initialize`, `tools/list`, and a harmless tool call.
- Official **Python `mcp`** SDK with the same OAuth and MCP flow.
- **`@modelcontextprotocol/inspector --cli`** for `tools/list` using the OAuth access token.

Negative checks cover tenant isolation, expired tokens, revoked agents, invalid OAuth redirect/PKCE, staff refusal, and plain `/mcp`. A dedicated step asserts SaaS opt-in authorize metadata (`saas_offered=1`) when `SAAS_SERVICE_URL` is set, and personal agent bearer tokens work on the matching company URL but fail on another company. A dedicated step asserts `POST /oauth/mcp/token` accepts `application/x-www-form-urlencoded` and refresh tokens. After OAuth clients run, `run_schema_audit.py` fails if any exported tool has an untyped or empty JSON Schema property (OpenAI/Gemini function-calling subsets: no bare `{}`, no top-level `anyOf`, objects with explicit `type` and `properties`).

Full cross-service audit (201 tools): [mcp-tool-schema-audit.md](mcp-tool-schema-audit.md). Regenerate with `uv run python tools/mcp-audit/generate_report.py` (requires sibling service checkouts under `.e2e-*` or CI fetch).

## Run locally (one command)

Clone [identity-service](https://github.com/shellui/identity-service) on `develop` next to ai-service (or set `IDENTITY_SRC`):

```bash
# layout: shellui/ai-service  shellui/identity-service
./tools/mcp-e2e/run.sh
```

Requirements: Docker, `uv`, Node 22+, network to pull base images. Ephemeral keys land in `tools/mcp-e2e/.e2e-secrets/` (gitignored): ai-service RS256 delegation material and identity `JWT_PRIVATE_KEY` / `JWT_KEY_ID` (RS256 is required for signed MCP revocation list responses; DEBUG-only HS256 identity is not enough for authenticated MCP traffic). Identity runs `seed_dev` only with `DEBUG=true` and `IDENTITY_DEV_SEED=true` inside compose.

Set `MCP_E2E_LEAVE_STACK=1` to keep containers running after a failure.

## CI

The **MCP client conformance** job on pull requests builds identity and ai-service, runs this script, and fails on any client or negative check.

**Repository variables (explicit refs, same semantics as the Tests job):**

| Variable | Default | Used by |
|----------|---------|---------|
| `IDENTITY_SERVICE_REF` | `develop` | MCP client conformance **and** Tests (schema audit) identity checkout |

The **Tests** job also accepts optional refs for downstream OpenAPI clones used only by `tools/mcp-audit/generate_report.py`: `STORAGE_SERVICE_REF`, `HOSTING_SERVICE_REF`, `EMAIL_SERVICE_REF`, `SAAS_SERVICE_REF` (each defaults to `develop`). Set these to a branch or **full commit SHA** when you need a locked contract across repos; the workflow prints no hidden partial pins—only what you configure in GitHub Actions variables for that run.
