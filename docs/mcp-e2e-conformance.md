---
title: MCP client conformance (e2e)
---

# MCP client conformance (e2e)

This suite proves the Shellui MCP gateway works with **official MCP clients**, not ai-service test doubles:

- `@modelcontextprotocol/sdk` (TypeScript) with OAuth protected-resource discovery, dynamic client registration, PKCE S256, magic-link sign-in, token exchange, refresh, `initialize`, `tools/list`, and a harmless tool call.
- Official **Python `mcp`** SDK with the same OAuth and MCP flow.
- **`@modelcontextprotocol/inspector --cli`** for `tools/list` using the OAuth access token.

Negative checks cover tenant isolation, expired tokens, revoked agents, invalid OAuth redirect/PKCE, staff refusal, and plain `/mcp`. A dedicated step asserts `POST /oauth/mcp/token` accepts `application/x-www-form-urlencoded` and refresh tokens.

## Run locally (one command)

Clone [identity-service](https://github.com/shellui/identity-service) on `develop` next to ai-service (or set `IDENTITY_SRC`):

```bash
# layout: shellui/ai-service  shellui/identity-service
./tools/mcp-e2e/run.sh
```

Requirements: Docker, `uv`, Node 22+, network to pull base images. Ephemeral keys land in `tools/mcp-e2e/.e2e-secrets/` (gitignored): ai-service RS256 delegation material and identity `JWT_PRIVATE_KEY` / `JWT_KEY_ID` (RS256 is required for signed MCP revocation list responses; DEBUG-only HS256 identity is not enough for authenticated MCP traffic). Identity runs `seed_dev` only with `DEBUG=true` and `IDENTITY_DEV_SEED=true` inside compose.

Set `MCP_E2E_LEAVE_STACK=1` to keep containers running after a failure.

## CI

The **MCP client conformance** job on pull requests builds identity (develop checkout) and ai-service, runs this script, and fails on any client or negative check.
