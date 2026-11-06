---
title: MCP gateway
---

# MCP gateway

## URLs and resource server

Each company has its own MCP URL: `POST /c/<company_id>/mcp`. OAuth protected-resource metadata
(RFC 9728) is at `GET /.well-known/oauth-protected-resource/c/<company_id>/mcp`. Unauthenticated
requests get `401`. Token `aud` must match the per-company URL and `company_id` must match
the path. Plain `/mcp` without a company returns `404` with `company_required`.

`tools/list` exports downstream tools as `<service>_<tool>`. Configure `AI_PUBLIC_URL` when behind a
proxy.

## Downstream access tokens

Gateway → identity: `POST /api/v1/mcp/internal/mcp-downstream-access-token` with RS256 from this
service (`AI_SERVICE_SIGNING_KEY`, `AI_SERVICE_ISSUER`, JWKS at `/.well-known/jwks.json`). Identity
mints `{ "access_token": "…" }`. The **same** key signs internal assertions (revocation poll,
call logs, approvals). Without it, revocation fails closed and call logs are skipped.

**Identity #135 coordination:** identity must validate the signed AI request against **current**
agent + resource, then `encode_access_token` embeds the **authoritative** global binding
(grant_version, company_binding_version, global_company_id) and caps access. Downstream services
must not invent binding from AI requests alone. Merge gateway and identity #135 changes in lockstep;
verify with integration tests on real payloads.

## MCP tool approvals (gateway)

**Flow:** (1) `mcp-approval-requests` with signed assertion. (2) `mcp-approval-decide`. (3)
`mcp-approval-consume` — only HTTP 2xx and JSON `consumed: true` (bool). (4)
`mcp-approval-session-check` on every eligible call (no local cache). (5) Optional
`mcp-approval-session-revoke`.

On `tools/call`, in-chat elicitation uses `_meta.shellui_approval`; client retries with
`params._meta.shellui_approval.decision` in `allow` | `deny` | `session_allow`. Gateway forwards
decisions to `mcp-approval-decide`.

### Global binding vs personal (regional JWT)

Do **not** infer mode from `personal_token_id` alone (identity #135 may issue it on global tokens).

| Mode | Rule |
|------|------|
| **Global delegated** | Canonical `global_company_id` **and** `grant_version` **and** `company_binding_version` (each strict nonnegative int, `0` allowed). |
| **Personal / legacy** | None of the three parsed as above; optional `personal_token_id` + `jti` for personal flows. |
| **Reject** | Any **partial** triple (e.g. gv without gcid, malformed UUID string, one version missing). |

Session-check POST body repeats binding fields **from the regional JWT only** (no stored authority).
For global tokens, Identity response must echo **exact** `global_company_id`, `grant_version`, and
`company_binding_version`. Invalid `setup_flow` blocks **all** approval APIs (`blocked_assertion`).

**Ordinary grant:** `expires_at` within ~60s; caps include JWT `exp` and setup bounds where applicable.

**commons pin:** `shellui-django[mcp]` @ `1f0754b421688ed26b7eb2e76b25b6fa3eea2a37` (`pyproject.toml`).

## Call logs (activity)

`POST /api/v1/mcp/internal/mcp-call-logs` with RS256. Fields are allowlisted; `operation_title` from
registry `_meta.operation_summary`; `path` / `resource_label` from static `_meta.path` (no client
query). HTTP 200 with `is_error` can map to `outcome: failed` with allowlisted `error_code`.
`client_ip` from the HTTP request only.

## Client conformance

See [mcp-e2e-conformance.md](./mcp-e2e-conformance.md) and [mcp-tool-schema-audit.md](./mcp-tool-schema-audit.md).
