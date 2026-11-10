---
title: MCP gateway handbook
---

# MCP gateway handbook

:::note

MCP is in Beta. Tool names and behavior may still change.

:::

This document describes how the **ai-service MCP gateway** behaves in this repository: URLs, tokens, approvals, session grants, tool naming, and what gets sent to Identity for activity. It is the operational reference for gateway code in `apps/connector/mcp_*.py`, not a status log for other projects.

Longer backend-oriented examples and request field lists: [mcp-handbook.md](./mcp-handbook.md).

## Public URL and company scope

- **Per-company MCP endpoint:** `POST /c/<company_id>/mcp` where `company_id` is the **numeric regional** company id (integer in the path and JWT `company_id` claim).
- **OAuth protected-resource metadata (RFC 9728):** `GET /.well-known/oauth-protected-resource/c/<company_id>/mcp` (also the trailing-slash and `/c/<company_id>/mcp/.well-known/oauth-protected-resource` forms). `authorization_servers` is `IDENTITY_ISSUER` (Identity's metadata `issuer`). `scopes_supported` is `mcp`. The origin-root well-known URL stays `404` `company_required`.
- **Unauthenticated** `GET` and `POST` get `401` with `WWW-Authenticate: Bearer realm="mcp", resource_metadata="<that document>", scope="mcp"`. Token `aud` must match the per-company URL and `company_id` must match the path. Device-grant access tokens use the same claims as authorization-code agent tokens and are accepted the same way. See [Device login](./mcp-device-login.md).
- **No company in path:** `POST /mcp` returns `404` with `company_required`.
- Behind a reverse proxy, set **`AI_PUBLIC_URL`** so metadata and redirects stay correct.

### Regional company id versus global delegation

- **Regional operations** use the **numeric** `company_id` in the URL and JWT (one regional tenant).
- **Global delegation** is a separate mode: the regional JWT can carry **`global_company_id`** (UUID) plus **`grant_version`** and **`company_binding_version`** when Identity has issued a delegated global agent token. The gateway does **not** treat `global_company_id` alone as proof of anything: **grant_version is not invented** for ordinary SaaS or global-cap tokens; it comes from Identity’s **authoritative** binding after exchange.
- **Direct resource** flows use regional scope; **delegated global** flows require Identity’s global binding fields in the regional token after the appropriate Identity exchange. Do not “guess” delegation from `personal_token_id` alone.

## Tool naming and the export surface

Downstream OpenAPI operations become MCP tools with stable names:

1. **Service-local name** comes from OpenAPI (`operationId` after normalization, optional `x-mcp.tool_name`, path/method fallback). See `resolve_mcp_tool_name` in `apps/connector/mcp_tool_naming.py`.
2. **Gateway export name** prefixes the service id: **`{service_id}_{local_name}`** (for example `storage_list_bucket` when `service_id` is `storage` and the local tool is `list_bucket`).

So the string the client passes to **`tools/call`** is always the **prefixed** export name.

Upstream `tools/list` may use any of these names for the same operation:

- the export name itself (`identity_create_groups`, `hosting_list_apps`, `email_create_newsletters`), including when that string is the OpenAPI `operationId` — kept as-is when it equals the name derived from the operation, and not prefixed again
- `x-mcp.tool_name` without the service prefix (`list_apps`) — the gateway adds `<service>_` once
- a legacy operationId slug (`api_v1_groups_create`, `storage_v1_bucket_list`, `hosting_v1_apps_list`) — mapped to that same export name

`tools/call` is forwarded with the name that upstream listed. Clients never see the legacy slug.

## Discovery instead of a 224-tool dump

By default **`tools/list`** returns a short set an agent can use to find the right operation:

1. **`ai_list_services`**: each connected service, a one-line summary, and example tasks. A tool count is included after the catalog has been loaded. This call does not fetch downstream services. If the count is missing, call `ai_search_tools` or `tools/list` first.
2. **`ai_search_tools`**: natural-language `query`, optional `service`, optional `access` (`read` or `write`), and `limit` (default 8, maximum 20). Matches include the name, description, read/write/destructive/approval flags, and the full input schema.
3. **`ai_describe_tool`**: full schema and a usage note for one or more tool names. Search and describe load the full catalog when it is missing or expired, through the same fetch, company scope, and cache lifetime as `tools/list?tools=all`. Each company has its own cache entry.
4. **`ai_call_tool`**: `{name, arguments}` runs that tool through the same tenant, scope, approval, masking, and audit path as a direct **`tools/call`**. In ask mode the person sees the real tool and its arguments.
5. **`ai_get_approval`**: `{approval_id}` reads one approval without running the tool. Use it to poll after you show the user the approval link. It does not consume the grant. When the status is `approved`, call the original tool again with the same arguments. That runs it once.
6. Four common reads, when that service is connected: `identity_list_users`, `storage_list_bucket`, `hosting_list_apps`, `email_list_messages`. They answer "who, what files, what apps, what mail" without a search.

Workflow: list services, search, then call. A direct **`tools/call`** of any of the 224 tools still works when that tool is not in the default list.

Opt in to the full catalog with **`POST /c/<company_id>/mcp?tools=all`**, or **`tools/list`** params **`{"tools": "all"}`**. Set **`MCP_TOOLS_LIST_MODE=all`** when a deployment should keep the full list as the default. The full list is still paged (200 tools per page, `nextCursor`). This gateway does not push `notifications/tools/list_changed`, because the HTTP session has no server-to-client stream. Change the URL or the list params and call **`tools/list`** again.

Example:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ai_search_tools","arguments":{"query":"invite a user","limit":3}}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ai_call_tool","arguments":{"name":"identity_create_invitations","arguments":{"method":"POST","path":"/api/v1/invitations/","body":{"email":"ada@example.com"}}}}}
```

**`tools/list`** in full mode exposes the operational export names and registry-derived `_meta` (path, method, `operation_summary`, access flags, etc.), plus the discovery tools (`ai_search_tools`, `ai_describe_tool`, `ai_call_tool`, `ai_get_approval`). **LiteLLM** or other inference stacks are **not** part of this gateway path; this document covers the gateway only.

## Bounded authority: `mcp_access` and tool safety

The agent JWT may carry **`mcp_access`** (default **`ask`**). The gateway combines that with **tool traits** (read-only vs write vs destructive) from registry metadata and annotations (`readOnlyHint`, `destructiveHint`, and `_meta.read_only` / `_meta.destructive` from OpenAPI **`x-mcp`**), via `decide_write` from shellui-django (`apps/connector/mcp_approval_gate.py`).

| Agent `mcp_access` (typical) | Read-only tools | Non-destructive writes | Destructive tools |
|-----------------------------|-----------------|-------------------------|-------------------|
| **`read_only`** | Allowed without approval | Denied | Denied |
| **`ask`** | Allowed without approval | Approval or session grant | Approval always (`mcp_destructive` does **not** bypass destructive operations) |
| **`full`** | Allowed | Allowed without approval for non-destructive | **Still requires approval** for destructive |

**Destructive** classification is driven by the **OpenAPI/registry** model, not by client-supplied labels. **`x-mcp`** on the operation is the supported way to mark `read_only` / `destructive`; clients must not rely on overriding limits via untrusted fields.

## Downstream access token (gateway to Identity)

The gateway calls Identity’s internal endpoint **`POST /api/v1/mcp/internal/mcp-downstream-access-token`** with an **RS256 service assertion** (`AI_SERVICE_SIGNING_KEY`, `AI_SERVICE_ISSUER`, JWKS at **`/.well-known/jwks.json`**). Identity returns **`{ "access_token": "…" }`** for calling downstream APIs.

The **same** signing material is used for other internal Identity calls (**revocation poll**, **call logs**, **approval** assertions). If signing is not configured, **revocation polling fails closed** (treat as blocked) and **call logs are skipped**; see `apps/connector/mcp_identity.py`.

## MCP approvals and session grants

### Endpoints (Identity)

1. **`mcp-approval-requests`:** create request; assertion is a signed JWT (includes binding: `company_id`, `agent_id`, `service`, `action`, `arguments_hash`).
2. **`mcp-approval-decide`:** user allow / deny / allow for session (`allow_session`).
3. **`mcp-approval-consume`:** **only** treat as consumed when HTTP **2xx** and JSON body has **`consumed: true`** (boolean).
4. **`mcp-approval-session-check`:** **no local cache** for grant validity on gated paths; gateway validates session with Identity using the **same** tool identity (`service`, **`action` = export name**, `arguments_hash`) and **`connection_id`** derived from **`Mcp-Session-Id`** (see below).
5. **`mcp-approval-session-revoke`:** optional revoke by `connection_id`.

### Client elicitation and retries

On **`tools/call`**, when approval is required, the gateway returns a tool result the agent can show in chat. `isError` is false. `structuredContent` and the text body use this shape:

```json
{
  "status": "pending",
  "approval_id": "<id>",
  "expires_at": "<iso-8601 or null>",
  "approval_url": "https://<identity>/oauth/mcp/approval/<id>",
  "instruction": "Show this link to the user and ask them to approve <tool>. After they approve, call this tool again with the same arguments. You can also call ai_get_approval with the approval_id to check the decision."
}
```

The text content starts with `Approval pending.` and includes the same JSON. `_meta.shellui_approval` repeats `approval_id`, `status`, `expires_at`, `approval_url`, and the settings list URL. Calling the same tool again with the same arguments after the person approves consumes the grant and runs the tool **once**. A second replay, a denial, or an expiry returns a clear message and does not run the tool.

`approval_url` is absolute. Identity `develop` at `d9539a7540f535c30bcbc4f70472e68d0edeb541` (PR **#149**) returns it on create and on state, on the public issuer (`JWT_ISSUER` / `IDENTITY_ISSUER`). The page is `GET /oauth/mcp/approval/<uuid>?token=<signed>`. The gateway uses that `approval_url` as sent. If a response omits it, the gateway joins the public issuer to `fallback_path` (the same path and token, relative). If that path is also absent, it builds `{issuer}/oauth/mcp/approval/{approval_id}`.

**Approval channels.** The channel is chosen per tool. Destructive tools (`destructiveHint`, registry `_meta.destructive`, or `DELETE`) always use the approval link. Read-only tools and other non-destructive writes use in-chat form elicitation when the client declared form mode (`capabilities.elicitation` empty, or `elicitation.form`). Clients that did not declare form mode get the link. A company can force the link for non-destructive tools with `MCP_APPROVAL_CHANNEL_BY_COMPANY` (JSON map of company id to `form` or `link`). That setting cannot turn a destructive tool into an in-chat approval. Identity has no per-company approval-channel field, so this override is gateway configuration.

In-chat consent trusts the MCP client. The gateway records Approve or Deny when the client sends `inputResponses.approval` with `action` `accept` and `content.decision` `approve`, or `deny` / `decline` / `cancel`. It does not see a separate human gesture. On Approve the gateway calls Identity `mcp-approval-decide` with `allow`, then consumes the grant and runs the tool once. On Deny it calls `deny`. The MCP `clientInfo.name` from `initialize` is written to the gateway log. Identity's decide route has no field for that client name or for an in-chat consent source, so the audit event is `client_allowed` or `client_denied` with optional `actor_email` only.

A client that still sends `params._meta.shellui_approval.decision` (`allow`, `deny`, or `session_allow`) is handled as before. **Approval-gated retries** must replay the **full** tool call (same export name and normalized arguments). Changing the action or normalized args requires a **new** approval.

Form elicitation (non-destructive, form-capable client):

```json
{
  "resultType": "input_required",
  "inputRequests": {
    "approval": {
      "method": "elicitation/create",
      "params": {
        "mode": "form",
        "message": "Allow storage_create_bucket? Choose Approve or Deny.",
        "requestedSchema": {
          "type": "object",
          "properties": {
            "decision": {
              "type": "string",
              "title": "Decision",
              "oneOf": [
                {"const": "approve", "title": "Approve"},
                {"const": "deny", "title": "Deny"}
              ]
            }
          },
          "required": ["decision"]
        }
      }
    }
  }
}
```

### URL elicitation

URL mode is `capabilities.elicitation.url` as an object (MCP spec 2025-11-25, and the current 2026-07-28 multi round-trip shape). An empty `elicitation` object is form mode only. The same declaration may arrive on a later request at `_meta["io.modelcontextprotocol/clientCapabilities"]`.

`shellui-django` 0.5.1, the server this gateway runs, returns one JSON-RPC body per POST. It has no server-to-client request channel, so it cannot push `elicitation/create` and then block the same HTTP response until the person finishes. The e2e client `@modelcontextprotocol/sdk` 1.32.2 understands URL params (`mode`, `url`, `message`, `elicitationId`) and the 2025 error `-32042`. It does not treat a tool result as an in-flight elicitation wait. The current spec (2026-07-28) instead puts URL elicitation on the tool result as `resultType: "input_required"`.

When the client declared URL mode, the pending tool result also includes:

```json
{
  "resultType": "input_required",
  "requestState": "<opaque>",
  "inputRequests": {
    "approval": {
      "method": "elicitation/create",
      "params": {
        "mode": "url",
        "elicitationId": "<token>",
        "url": "<approval_url>",
        "message": "Approve <tool> in your browser, then return here."
      }
    }
  }
}
```

The plain pending text is still present, so an agent that ignores `inputRequests` can show the link. If the client retries with `inputResponses.approval.action` of `accept`, the gateway polls Identity for up to `MCP_APPROVAL_URL_ELICITATION_WAIT_SECONDS` (default 20) and then runs the tool once if the grant is approved. `decline` or `cancel` returns a denial and does not run the tool. If the wait ends while the row is still pending, the gateway returns the pending tool result again and does not keep the HTTP call open. Clients that did not declare URL mode get that pending result immediately. Non-destructive tools whose client declared form mode use the in-chat form channel instead of this URL elicitation.

### When an approval cannot be created

The gateway does not return the bare text `Approval unavailable.` Failure text names the cause and does not include tokens, keys, or Identity response bodies:

| Cause | Text |
| --- | --- |
| Identity unreachable, or HTTP 5xx | Approval could not be requested because Shellui identity is unreachable. Try again shortly. |
| Signing key or issuer missing | Approval could not be requested because signing is not configured. |
| Blocked assertion (invalid setup claims or a global binding conflict) | Approval could not be requested because this agent cannot request approvals. |
| Identity origin unset | Approval could not be requested because Shellui identity is not configured. |
| Identity HTTP 4xx | Approval could not be requested. Shellui identity rejected the request. |
| Unexpected JSON | Approval could not be requested because Shellui identity returned an unexpected response. |

### Session grant rules (gateway behavior)

`check_session_grant` in `apps/connector/mcp_approvals.py` **fails closed**:

- **Destructive** tools: session grant **never** applies (`is_destructive=True` → deny immediately).
- **Identity errors/timeouts/non-2xx/invalid JSON:** deny (do **not** execute downstream on ambiguity).
- **Binding:** grant must match **agent_id**, **numeric company_id**, **service**, **`action` (export name)**, **`arguments_hash`**, and sanitized **`connection_id`**.
- **Revocation:** if the agent is revoked for that tenant in the trusted revocation snapshot, deny.
- **Delegated global:** response must echo **`global_company_id`**, **`grant_version`**, and **`company_binding_version`** exactly as in the trusted regional JWT claims; partial triples or version mismatch → deny. **Do not** add a default grant version for global-cap tokens that never went through Identity’s delegated binding. Before relying on the revocation snapshot alone, the gateway also calls Identity’s **live** internal check **`POST /api/v1/mcp/internal/mcp-agent-delegated-authority`** (assertion **`aud`:** `shellui-mcp-agent-delegated-authority`, **`scope`:** `mcp.agent.delegated.authority.read`); a trusting **200** must match Identity’s **fixed 15-key** success JSON (**`authorized`** and **`active`** true; **`revoked`** / **`paused`** / **`allow_destructive`** false; sorted **`services_allowed`**; no extra keys—see [mcp-handbook.md](./mcp-handbook.md)).
- **Setup flow:** `setup_flow` and **`setup_expires_at`** from Identity’s response are enforced; the gateway does **not** trust a setup **`true`** in an **old** JWT alone as authoritative. Persisted setup state is **Identity’s** (session-check / consume contract). **Refresh** may **narrow** expiry but must not extend past caps (JWT wall, ordinary ~60s grant for non-setup, setup TTL ceiling).
- **Deny/supersede:** a **deny** or **revoke** invalidates prior allows; **pause** / **narrow** changes should invalidate earlier session decisions (enforced by Identity + version checks on the gateway side).

### `connection_id` (sanitized for Identity only)

`identity_connection_id` in `apps/connector/mcp_approvals.py`: printable ASCII, max **128** characters, no **`|`**; otherwise **SHA-256** hex of the UTF-8 **raw** `Mcp-Session-Id`. The local session cache may still use the raw header value.

### Signed assertions: trusted fields only

Internal approval assertions are built with **`build_mcp_approval_assertion`** (commons / shellui-django). For **delegated** mode, **grant_version**, **global_company_id**, and **company_binding_version** are taken from **strictly parsed** regional JWT claims (`ApprovalAssertionContext`), not from raw request bodies or unverified client overrides. Identity compares **service snapshot / persisted versions** to what the gateway asserts; the gateway must **not** accept raw JWT passthrough or untrusted body fields for that binding.

## Global binding detection (strict)

Logic lives in `apps/connector/mcp_setup_context.py`:

- **Global delegated** only when **`global_company_id`** is a canonical UUID **and** **`grant_version`** **and** **`company_binding_version`** are each a **non-negative int** (including **`0`**).
- **Reject** on any **partial** triple or malformed UUID string. A personal token that carries only **`grant_version`** (no **`global_company_id`**, no **`company_binding_version`**, and **`mcp_authority`** not **`delegated`** or **`global_delegated`**) is not a partial triple. Its approval assertion still includes that **`grant_version`**. Invalid setup claims stay blocked.
- **`personal_token_id`** may appear on delegated tokens; **do not** infer delegation from it alone.

**commons pin:** `shellui-django[mcp]` is pinned in `pyproject.toml` / `uv.lock` (see the repo for the current revision).

## Call logs and activity (Identity)

`POST /api/v1/mcp/internal/mcp-call-logs` tracks **downstream MCP tool execution** against **identity-service `develop`** (e.g. `bdb3c3` on `McpInternalCallLogView` + `canonical_call_path` in `call_log_internal.py`). The gateway sends only what Identity accepts for **remote** ingest: **`agent_id`**, **`company_id`**, **`grant_version`** (must match the agent JWT), **`service`**, **`tool`**, wire **`method`: `POST`** and **`path`: `/mcp`** (so Identity can build `POST /mcp (service)` resource labels—**not** REST templates or query strings), **`status`**, **`duration_ms`**, **`outcome`**, **`access_kind`**, optional **`approval_id`** (UUID only), and optional **`error_code`** from Identity’s allowlist (`apps/agents/mcp_audit_codes.py`). **No** `client_ip`, **`result`**, `operation_title`, `resource_label`, `arguments`, or **`approval_request_id`**. **Delegated** agents (JWT has full `global_company_id` + `company_binding_version` + `grant_version` triple): forward includes **`global_company_id`** and **`company_binding_version`** and must match the JWT; **personal / non-delegated** forwards omit both. If the JWT lacks **`grant_version`** or the entry disagrees with claims on company or binding, **`forward_call_log` sends nothing** (avoids inventing versions).

**Destructive tools:** Identity only accepts **`access_kind`: `destructive`** with **`outcome`** **`allowed`** or **`session_used`** and a matching **`approval_id`** for an approved destructive row. On any other outcome the gateway **drops `approval_id`**, sets **`outcome`** to **`failed`**, and attaches an **`error_code`** (never a false success with a pending/waiting destructive approval).

### Gateway **`outcome`** vs Identity ingest

Internal rows still use **`OUTCOMES`** in `mcp_call_audit.py`. **`forward_call_log`** maps those to Identity’s five ingest outcomes; see `_identity_ingest_outcome` in `apps/connector/mcp_identity.py`.

### Safe metadata only

- **Wire route:** always **`POST /mcp`** on forward; OpenAPI **method/path** stay in local audit only.
- **Labels:** **`company_name`** and **`agent_name`** are **not** forwarded (JWT display strings are not server-enforced registry data).
- **`access_kind`:** **`read`**, **`write`**, **`destructive`**, or **`unknown`** from tool traits and HTTP method (`access_kind_from_tool`).
- **No** raw tool arguments: sending `arguments` or `arguments_redacted` on an approval create returns **400**. A redacted `arguments_summary` string (max 500 characters) is the only argument text Identity accepts, and only on that create.

A downstream HTTP **2xx** alone does **not** imply **`allowed`** if the gateway classified the operation as an error (`is_error`, audit `log_result`, etc.). See **`outcome_from_audit`**.

### Approvals: state before create, retry, and bodies

On each gated **`tools/call`**, the gateway calls **`mcp-approval-state`** first (empty JSON body; binding is **only** in the signed assertion). Identity **200** is always `id`, `status` (`pending`, `approved`, `denied`, or `expired`), `expires_at`, `is_destructive`, and absolute `approval_url`. `404` means no row. The `id` is kept for every status so a pending or approved row is not created again.

- **Create** (`mcp-approval-requests`): JSON body is `is_destructive` (boolean) and, when there is a safe redacted preview, `arguments_summary` (string, at most 500 characters). Identity stores that summary on `short_action_summary` and shows it on the approval page. Never send `arguments`, `arguments_redacted`, `target`, `short_action_summary`, `path`, or `method`.
- **State** (`mcp-approval-state`): empty JSON body. Use the returned `approval_url` and `expires_at`.
- **Decide** (`mcp-approval-decide`): includes `approval_id`, `decision`, sanitized `connection_id`, optional `actor_email`.
- **Consume** (`mcp-approval-consume`): JSON **`{ "approval_id": "…" }`** only.

See **`test_mcp_identity_conformance`** for a mocked Identity round-trip (state → pending → allow → consume) that asserts those body shapes.

### Coordinator: sibling services (storage / hosting / email)

Other service gateways that write MCP approvals or forward activity to Identity should match the same contract: **no** `arguments` or `arguments_redacted` on approval creates; binding only in signed assertions; **live** delegated-authority checks where applicable; and activity fields from **registry `_meta`** only. This repo does not change those PRs; align their gateways independently.

## Client conformance and CI

- **Conformance and audits:** [mcp-e2e-conformance.md](./mcp-e2e-conformance.md), [mcp-tool-schema-audit.md](./mcp-tool-schema-audit.md).
- **MCP e2e scope:** the `tools/mcp-e2e` compose stack leaves storage, hosting, and email URLs empty by default and uses a **SaaS mock**. See [mcp-e2e-conformance.md](./mcp-e2e-conformance.md). You may set `STORAGE_SERVICE_URL`, `HOSTING_SERVICE_URL`, `EMAIL_SERVICE_URL`, or `SAAS_SERVICE_URL` in the environment before `docker compose` for local full-path checks. Do not treat a green **MCP client conformance** job as full-stack or regional-delegated-downstream proof unless CI is extended and you document the refs you pinned.
- **CI** checks out **`shellui/identity-service`** at **`develop`** by default unless the repository variable **`IDENTITY_SERVICE_REF`** is set (branch name or full SHA). To align with **identity PR #135** while it is open, pin that PR’s **current** `headRefOid` from GitHub (it moves with pushes). Record the **exact ref you validated** in the **pull request description** for traceability.

## Unsupported / transport notes

- **`resources/`** and **`templates/`** are not used as generic MCP transports here; tool responses follow the **text** / structured content patterns enforced by the Django MCP integration.
- Downstream adapters must treat broker and HTTP errors as **untrusted** for user-visible text; the gateway redacts and maps to allowlisted **error_code** values where applicable.
