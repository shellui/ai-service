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

Session allow skips re-prompts for **non-destructive** writes on the same `Mcp-Session-Id` connection. **Every** eligible `tools/call` performs `POST /api/v1/mcp/internal/mcp-approval-session-check` (the gateway does not cache a local “already allowed” boolean). The JSON body always includes `connection_id`, `agent_id`, `company_id`, `service`, `action`, `arguments_hash`, and `is_destructive`. **`grant_version` and `company_binding_version`** come from the live regional token when present (including canonical string **`"0"`** and integer **`0`** in JWT claims—they are normalized to strings for the wire). **Delegated** tokens (no `personal_token_id`) **must** supply both versions on the token and in this body; **personal** tokens (`personal_token_id` set) may omit both keys when identity has not bound global versions yet. If one version is present and the other is absent, the check fails closed.

Signed approval assertions (`create` / `state` / `decide` / `consume` / session-check) include `grant_version` and `company_binding_version` in the JWT whenever the token provides them (again including **`0`** / **`"0"`**—never dropped because of a “falsy” check). **Delegated** agents that claim `setup_flow` but fail validation (wrong grant shape, missing `setup_expires_at`, out-of-range TTL, etc.) do **not** fall back to an ordinary 60s assertion: internal approval calls are skipped (fail closed) so a bad setup claim cannot be laundered through normal approval APIs.

A grant is honored only when **all** of the following hold:

- Response `session_allowed` is true **and** `grant_version` and `company_binding_version` **exactly** match the verified regional access token (no alias keys).
- Response includes an absolute `expires_at` within **60 seconds** of “now” for ordinary sessions.
- **Setup** (long allow) applies only when the token includes `setup_flow: true`, `mcp_new_company_grant: true`, signed `mcp_session_ttl_seconds` in **600–900**, absolute `setup_expires_at` on the token, **and** matching `setup_expires_at` on the session-check response; if the access token has **≤600s** wall time remaining, setup long-allow is **not** used (fall back to ordinary 60s rules). Caps still include JWT `exp` wall and signed setup expiry.
- Destructive tools never use session allow (even when `mcp_access` is `full` or `mcp_destructive` is set).

**Deny precedence:** a client `deny` decision is sent to Identity **before** any session-grant shortcut is evaluated (deny cannot be overridden by an active session grant).

Revoke with `mcp-approval-session-revoke`. Approved one-shot calls still use `mcp-approval-consume`.

### Call logs (personal activity / audit)

Gateway forwards `POST /api/v1/mcp/internal/mcp-call-logs` with RS256 assertions. The JSON body extends the historical shape with **allowlisted** audit fields (identity **#135** must persist them for the personal activity API):

| Field | Notes |
| ----- | ----- |
| `outcome` | Gateway uses `allowed` \| `failed` \| `denied` \| `pending` \| `session_used`. Forwarded to identity as `pending_approval` when the gateway outcome is `pending` (identity region activity schema). |
| `access_kind` | `read` if method is GET/HEAD/OPTIONS **or** explicit `readOnlyHint` / `_meta.read_only`; `destructive` if explicit `destructiveHint` / `_meta.destructive` (non-safe method); else `write` — not inferred from name or substring heuristics |
| `read_only_hint`, `destructive_hint` | Mirrors MCP tool annotations |
| `operation_title` | Trusted OpenAPI `summary` from registry `_meta.operation_summary` (or presentation `title` when non-sensitive); if missing or unsafe, neutral `Operation {export_name}` (never raw provider exception text) |
| `tool_export_id` | Same as gateway export name (`tool`) |
| `resource_label` | `METHOD` + trusted route template from `_meta.path`, or sanitized path with query/fragment stripped |
| `path` | Same sanitized route as `resource_label` (no `?` or `#`; never raw client query strings) |
| `error_code` | Optional; allowlisted only: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `rate_limited`, `timeout`, `upstream_error`, `internal_error`, `denied`, `expired`, `out_of_sync`, `unknown`. Arbitrary provider strings are dropped. |
| `company_name`, `agent_name` | From validated access-token claims when present |
| `approval_id` | Set when a real approval row id is known (e.g. pending elicitation) |
| `result` | Legacy short token forwarded only when already one of `success`, `error`, `denied`, `pending`; otherwise recomputed from `outcome` (never arbitrary text) |
| `duration_ms` | Unchanged |

`company_id` always matches the token; if the tool call’s service id and a `service` claim on the token both exist and differ, `outcome` is `failed` (no cross-service leakage).

Arguments, query bodies, provider response text, and headers are **never** forwarded.

Identity must implement the internal approval and session-check contract described here; ai-service tracks that contract in PR **#24** (merge into `develop` — this doc is the gateway contract as implemented in that PR, not a future branch guess).

## Client conformance

Official MCP clients (TypeScript SDK, Python SDK, MCP Inspector CLI) are exercised end-to-end in CI. See [MCP client conformance (e2e)](./mcp-e2e-conformance.md) and run `./tools/mcp-e2e/run.sh` locally.

Cross-service tool `inputSchema` audit (201 tools, Inspector-aligned): [mcp-tool-schema-audit.md](./mcp-tool-schema-audit.md).
