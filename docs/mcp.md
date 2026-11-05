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

Session allow skips re-prompts for **non-destructive** writes for **60 seconds** on the same `Mcp-Session-Id` connection. Identity tracks grants; the gateway checks `POST /api/v1/mcp/internal/mcp-approval-session-check` (and can revoke with `mcp-approval-session-revoke`). Approved one-shot calls still use `mcp-approval-consume`. Call logs forwarded to identity include audit-style `result` values such as `client_allowed`, `client_denied`, `client_session_allowed`, `approved`, `denied`, `expired`, and `pending`.

Requires identity PR **#134** (or equivalent) for decide and session-check endpoints; create, state, and consume match identity `develop` today.

## Client conformance

Official MCP clients (TypeScript SDK, Python SDK, MCP Inspector CLI) are exercised end-to-end in CI. See [MCP client conformance (e2e)](./mcp-e2e-conformance.md) and run `./tools/mcp-e2e/run.sh` locally.

Cross-service tool `inputSchema` audit (201 tools, Inspector-aligned): [mcp-tool-schema-audit.md](./mcp-tool-schema-audit.md).
