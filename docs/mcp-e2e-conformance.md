---
title: MCP client conformance (e2e)
---

# MCP client conformance (e2e)

## What this page covers

You run `tools/mcp-e2e` to exercise the **ai-service** MCP gateway against **identity-service** with **official MCP clients** (TypeScript SDK, Python SDK, inspector). Default Docker Compose leaves **storage**, **hosting**, and **email** MCP URLs empty and uses a **SaaS mock**. This page states exactly what is verified and what is not.

## No full downstream stack required

The default `tools/mcp-e2e` run is **not** an optional compose profile that you must “turn on” to get a complete stack. **Storage, hosting, and email MCP backends are absent by default** (`STORAGE_SERVICE_URL` / `HOSTING_SERVICE_URL` / `EMAIL_SERVICE_URL` empty). Conformance is **identity + ai gateway + OAuth + MCP clients** only; **real downstream MCP services are out of scope** unless you manually set URLs (see below).

## What the default stack exercises

The compose file `tools/mcp-e2e/docker-compose.yml` starts **identity**, **ai-service**, **postgres**, **redis**, and **`saas-mock`**.

On the **ai** service, **`STORAGE_SERVICE_URL`**, **`HOSTING_SERVICE_URL`**, and **`EMAIL_SERVICE_URL`** default to **empty**, so the gateway does **not** register or call those MCP backends in the default run. **`SAAS_SERVICE_URL`** defaults to **`http://saas-mock:8000`** (not production SaaS).

So the default suite proves **MCP + OAuth + ai gateway + identity** for the flows in `tools/mcp-e2e` (including negatives such as tenant isolation, revoked agents, and invalid OAuth where the scripts cover them). It does **not** prove routing through real **storage**, **hosting**, or **email** gateways, full delegated-downstream integration, or production SaaS behavior.

The default `tools/list` result is the discovery set. `?tools=all` returns everything.

The gateway **`initialize`** response echoes **`protocolVersion`** when the client sends one of the revisions in `apps.connector.mcp_protocol.SUPPORTED_PROTOCOL_VERSIONS`. A newer revision, such as the official SDK's `2025-11-25`, is answered with the newest revision this gateway implements (`2025-06-18`). A missing version is still **JSON-RPC -32600**. Default CI still uses empty downstream URLs and the SaaS mock, so **live** delegated downstream MCP is not exercised automatically.

## Optional downstream URLs (manual local evidence only)

Before `docker compose up`, you can point the **ai** container at real sibling dev URLs (each must serve MCP as your env expects). This is **ad hoc** and **not** part of the default CI MCP client job:

| Variable | Default in compose | Notes |
|----------|-------------------|--------|
| `STORAGE_SERVICE_URL` | empty | Set to e.g. `http://host.docker.internal:PORT/mcp` if you run storage-service on the host. |
| `HOSTING_SERVICE_URL` | empty | Same pattern for hosting-service. |
| `EMAIL_SERVICE_URL` | empty | Same pattern for email-service. |
| `SAAS_SERVICE_URL` | `http://saas-mock:8000` | Set to a real **saas-service** base URL only if you run that stack; omit or override to test opt-in metadata against a real server. |

Example (bash, before `./tools/mcp-e2e/run.sh`):

```bash
export STORAGE_SERVICE_URL=http://host.docker.internal:9001/mcp
export HOSTING_SERVICE_URL=http://host.docker.internal:9002/mcp
export EMAIL_SERVICE_URL=http://host.docker.internal:9003/mcp
./tools/mcp-e2e/run.sh
```

Record the **exact SHAs or branch names** of identity, saas, storage, hosting, and email you used. **PR heads move**; re-check with `gh pr view <N> --repo shellui/<repo> --json headRefOid` before you pin a ref.

**Open PR heads at last check (re-run `gh pr view <N> --repo shellui/<repo> --json headRefOid` before you rely on a pin):**

| Repo | PR | headRefOid (last `gh` check in ai-service CI docs) |
|------|-----|-----------------------------------------------------|
| shellui/identity-service | #135, #138 (`b53ebbd`), and #139 merged. Closed #136 and #137 are not the contract. Revocation JSON echoes signed `max_active_grant_version` and full agent snapshots (`a7708eb`, merge `6a0c6a0`). | `6a0c6a0354d4ef79491f332e3c25c8b19d98084f` (`develop` after #139) |
| shellui/storage-service | #59 | `6db93f833fa1f0f747a686ede9c1c4e974301fea` |
| shellui/hosting-service | #78 | `71403d9c3cd6ffa3a0ee6d561662070ad31e0581` |
| shellui/email-service | #46 | `17c900d07938f5fbd15a0241ba6e58d8a704c9d0` |
| saas-service (org private / not in public `gh` list) | #34 | Set `SAAS_SERVICE_REF` to the **current** PR head (maintainer-cited example: `1ca91a…` full SHA from your `gh pr view`) |

The **Tests** job checks out `shellui/saas-service` with `continue-on-error: true` because that repository may be unreadable from a token with only public-repo scope; schema audit then omits SaaS unless the checkout succeeds.

CI **MCP client conformance** still uses empty downstream URLs and the SaaS mock unless you change the workflow; `IDENTITY_SERVICE_REF` (and sibling refs for the **Tests** job schema audit) stay the way to pin identity in GitHub Actions. The gateway stores tool-call logs itself and does not POST them to identity `/api/v1/mcp/internal/mcp-call-logs`. Destructive **`allowed`** / **`failed`** keep the consumed approval id and leave that row **executed**; a duplicate consume is **`failed`** with that same id, not a second success and not **`session_used`**. **`denied`** / **`waiting_approval`** stay **`access_kind: destructive`** and may link a pending or rejected row. The delegated-authority **200** body stays the fixed 15 keys from **#135**. The revocation poll JSON must echo signed **`max_active_grant_version`** and the agent snapshots. The gateway does not invent that field. Identity **`develop`** `6a0c6a0` (#139) does.

**Live HTTP proof (human OAuth, narrowed approval, masked activity)** is out of scope for default CI and was not run in this agent environment: terms/sign-up stay on the human SaaS shell; do not add one-off DB inserts or auto-approvals beyond sanctioned dev seeds.

## What the clients run

This suite drives **official MCP clients** against ai-service, not ai-service-only mocks:

- `@modelcontextprotocol/sdk` (TypeScript) with OAuth protected-resource discovery, dynamic client registration, PKCE S256, magic-link sign-in, token exchange, refresh, `initialize`, `tools/list`, and a harmless tool call.
- Official **Python `mcp`** SDK with the same OAuth and MCP flow.
- **`@modelcontextprotocol/inspector --cli`** for `tools/list` using the OAuth access token.
- **Device login** (`clients/run_device_flow.py`): protected-resource discovery and the 401 challenge, then (when Identity advertises `device_authorization_endpoint`) device-code start, the same magic-link approval the other clients use, token poll, and `tools/call`. Against an Identity build that does not advertise device authorization, that round-trip is skipped after the discovery checks.

Negative checks cover tenant isolation, expired tokens, revoked agents, invalid OAuth redirect/PKCE, staff refusal, and plain `/mcp`. A step asserts SaaS opt-in authorize metadata (`saas_offered=1`) when `SAAS_SERVICE_URL` points at a server that returns that metadata (the default mock satisfies the shape the script expects). A step asserts `POST /oauth/mcp/token` accepts `application/x-www-form-urlencoded` and refresh tokens. After OAuth clients run, `run_schema_audit.py` fails if any exported tool has an untyped or empty JSON Schema property (OpenAI/Gemini function-calling subsets: no bare `{}`, no top-level `anyOf`, objects with explicit `type` and `properties`).

Full cross-service audit (many tools): [mcp-tool-schema-audit.md](mcp-tool-schema-audit.md). Regenerate with `uv run python tools/mcp-audit/generate_report.py` (requires sibling service checkouts under `.e2e-*` or CI fetch).

## Run locally (one command)

Clone [identity-service](https://github.com/shellui/identity-service) on `develop` next to ai-service (or set `IDENTITY_SRC`):

```bash
# layout: shellui/ai-service  shellui/identity-service
./tools/mcp-e2e/run.sh
```

Requirements: Docker, `uv`, Node 22+, network to pull base images. Ephemeral keys land in `tools/mcp-e2e/.e2e-secrets/` (gitignored): ai-service RS256 delegation material and identity `JWT_PRIVATE_KEY` / `JWT_KEY_ID` (RS256 is required for signed MCP revocation list responses; DEBUG-only HS256 identity is not enough for authenticated MCP traffic). Identity runs `seed_dev` only with `DEBUG=true` and `IDENTITY_DEV_SEED=true` inside compose.

Set `MCP_E2E_LEAVE_STACK=1` to keep containers running after a failure.

## CI

The **MCP client conformance** job on pull requests uses the same **default** compose constraints (empty storage, hosting, email URLs; SaaS mock unless the workflow changes). It builds identity and ai-service, runs this script, and fails on any client or negative check. That job validates **identity + ai + official clients** in this narrow configuration, not delegated-downstream behavior against real sibling services unless CI is extended.

**Repository variables (explicit refs, same semantics as the Tests job):**

| Variable | Default | Used by |
|----------|---------|---------|
| `IDENTITY_SERVICE_REF` | `develop` | MCP client conformance and Tests (schema audit) identity checkout |

The **Tests** job also accepts optional refs for downstream OpenAPI clones used only by `tools/mcp-audit/generate_report.py`: `STORAGE_SERVICE_REF`, `HOSTING_SERVICE_REF`, `EMAIL_SERVICE_REF`, `SAAS_SERVICE_REF` (each defaults to `develop`). Set these to a branch or full commit SHA when you need a locked OpenAPI contract across repos; the workflow does not hide pins - only what you set in GitHub Actions variables applies.
