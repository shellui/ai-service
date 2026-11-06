---
title: MCP gateway
---

# MCP gateway

Each company has its own MCP URL: `POST /c/<company_id>/mcp`, for example `https://ai.shellui.com/c/42/mcp`. Find it in the admin AI panel.

- OAuth protected-resource metadata (RFC 9728) lives at `GET /.well-known/oauth-protected-resource/c/<company_id>/mcp`. Its `resource` is that exact per-company URL, and the authorization server is identity. When `SAAS_SERVICE_URL` is set, metadata includes `shellui_mcp_authorize_query: {"saas_offered": "1"}` so MCP OAuth clients append `saas_offered=1` on identity `GET /oauth/mcp/authorize` (optional SaaS access at consent).
- An unauthenticated request gets `401` with a `WWW-Authenticate: Bearer resource_metadata="…"` header pointing at that metadata.
- An access token is accepted only when its `aud` is the per-company URL and its `company_id` claim equals the company in the URL. A token for another company is refused, even if it is otherwise valid.
- Identity refuses to authorize a resource for a company that does not exist, so no token can ever exist for one; such a URL only ever answers `401`.
- Plain `/mcp` and `/.well-known/oauth-protected-resource` never pick a default company. They return `404` with `{"error": "company_required"}`.

`tools/list` keeps the gateway's own tools as they are and exports every downstream tool as `<service>_<tool>` (single underscore), for example `storage_list_buckets` or `saas_list_projects`.

`AI_PUBLIC_URL` sets the public origin used in the resource (defaults to `AI_SERVICE_ISSUER`). Set it whenever the service runs behind a proxy, since the request Host is never trusted for the audience.

When the gateway calls a downstream service `/mcp`, it asks identity to mint a short-lived agent access token. ai-service signs that request with its own RS256 key (`shellui_django.mcp.delegation.sign_downstream_token_request`), not identity’s `SECRET_KEY`:

- Configure `AI_SERVICE_SIGNING_KEY` (or `AI_SERVICE_SIGNING_KEY_FILE`), `AI_SERVICE_SIGNING_KID`, and `AI_SERVICE_ISSUER`.
- Publish the public key at `GET /.well-known/jwks.json`.
- Generate keys: `python manage.py generate_signing_key` (or `--shell` for eval-friendly exports).

The same key signs internal assertions to identity (revocation polling and call logs, `shellui-django` 0.4.0+). Identity trusts them only from the issuer in its `AI_SERVICE_ISSUER` and verifies them with this JWKS. Without a signing key, revocation polling fails closed (every agent is treated as revoked) and call logs are skipped.

Identity endpoint: `POST /api/v1/mcp/internal/mcp-downstream-access-token`. It validates the bearer JWT using ai-service JWKS and `AI_SERVICE_ISSUER`, then returns `{ "access_token": "…" }`.

## MCP tool approvals (gateway)

On `tools/call`, the gateway enforces the agent `mcp_access` mode (`read_only`, `ask`, `full`) and tool annotations (`readOnlyHint`, `destructiveHint`). Writes that need a human decision create a row in identity via `POST /api/v1/mcp/internal/mcp-approval-requests`, then either:

- **In-chat (elicitation):** the tool result includes `_meta.shellui_approval` with Wilson v1 copy and buttons Allow, Deny, and Allow for this session (non-destructive only). The client retries `tools/call` with `params._meta.shellui_approval.decision` set to `allow`, `deny`, or `session_allow`. The gateway records the decision through identity `POST /api/v1/mcp/internal/mcp-approval-decide` (`allow`, `deny`, or `allow_session`; `409` when session allow is requested for a destructive tool).
- **Settings fallback:** when the MCP session did not advertise elicitation, the result points at identity `GET /api/v1/mcp/approvals` (list) and the specific approval id under `/api/v1/mcp/approvals/{id}`.

Session allow skips re-prompts for **non-destructive** writes on the same `Mcp-Session-Id` connection. **Every** eligible `tools/call` performs `POST /api/v1/mcp/internal/mcp-approval-session-check` (the gateway does not cache a local “already allowed” boolean). A grant is honored only when **all** of the following hold:

- Response `session_allowed` is true **and** `grant_version` and `company_binding_version` match the verified regional access token (aliases such as `grant_validity_version` are not accepted).
- Response includes an absolute `expires_at` within **60 seconds** of “now” for ordinary sessions; setup sessions use the **600–900** second window from signed claims and also require `setup_expires_at` on the response, capped by JWT wall time and signed setup expiry.
- Destructive tools never use session allow (even when `mcp_access` is `full` or `mcp_destructive` is set).

Revoke with `mcp-approval-session-revoke`. Approved one-shot calls still use `mcp-approval-consume`.

### Call logs (personal activity / audit)

Gateway forwards `POST /api/v1/mcp/internal/mcp-call-logs` with RS256 assertions. The JSON body extends the historical shape with **allowlisted** audit fields (identity **#135** must persist them for the personal activity API):

| Field | Notes |
| ----- | ----- |
| `outcome` | `allowed` \| `failed` \| `denied` \| `pending` \| `session_used` — derived from gateway decisions / HTTP status, not from raw error text |
| `access_kind` | `read` \| `write` \| `destructive` from tool annotations + HTTP method |
| `read_only_hint`, `destructive_hint` | Mirrors MCP tool annotations |
| `operation_title` | OpenAPI/registry title when present (stripped presentation noise); otherwise empty (UI may fall back to tool id) |
| `tool_export_id` | Same as gateway export name (`tool`) |
| `resource_label` | Short `METHOD path` (no arguments) |
| `company_name`, `agent_name` | From validated access-token claims when present |
| `approval_id` | Set when a real approval row id is known (e.g. pending elicitation) |
| `result` | Legacy short token (`success` / `error` / `denied` / `pending`) for backward compatibility |
| `duration_ms` | Unchanged |

`company_id` always matches the token; if the tool call’s service id and a `service` claim on the token both exist and differ, `outcome` is `failed` (no cross-service leakage).

Arguments, query bodies, provider response text, and headers are **never** forwarded.

Identity must implement the internal approval and session-check contract (`grant_version`, `company_binding_version`, `setup_expires_at` when setup); create, state, consume, decide, session-check, and call logs align with identity `develop` after merge.

## Client conformance

Official MCP clients (TypeScript SDK, Python SDK, MCP Inspector CLI) are exercised end-to-end in CI. See [MCP client conformance (e2e)](./mcp-e2e-conformance.md) and run `./tools/mcp-e2e/run.sh` locally.

Cross-service tool `inputSchema` audit (201 tools, Inspector-aligned): [mcp-tool-schema-audit.md](./mcp-tool-schema-audit.md).
