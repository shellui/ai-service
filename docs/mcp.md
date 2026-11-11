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

Workflow: list services, search, then call. A direct **`tools/call`** of any of the 224 tools still works when that tool is not in the default list. The route cache and the tools list share one TTL, but a route lookup can refresh only the route key. The next call then still has a route after the list has expired. The gateway treats that as a miss and loads `tools/list` for that service again before it decides the tool is unknown. The error text says the tool was not found, or that the catalog could not be loaded. It does not say `Tool call rejected.`

Opt in to the full catalog with **`POST /c/<company_id>/mcp?tools=all`**, or **`tools/list`** params **`{"tools": "all"}`**. Set **`MCP_TOOLS_LIST_MODE=all`** when a deployment should keep the full list as the default. The full list is still paged (200 tools per page, `nextCursor`). This gateway does not push `notifications/tools/list_changed`, because the HTTP session has no server-to-client stream. Change the URL or the list params and call **`tools/list`** again.

Example:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ai_search_tools","arguments":{"query":"invite a user","limit":3}}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ai_call_tool","arguments":{"name":"identity_create_invitations","arguments":{"email":"ada@example.com"}}}}
```

**`tools/list`** in full mode exposes the operational export names and the discovery tools (`ai_search_tools`, `ai_describe_tool`, `ai_call_tool`, `ai_get_approval`). Each tool's `inputSchema` is a flat list of named arguments. HTTP `method` and `path` are not arguments. The gateway fills them from the registry when it forwards the call, and it ignores them if an agent sends them. Path parameters keep their OpenAPI `format`, `enum`, and description. Query, body, and path fields keep `enum`, `format`, `description`, `minimum`, `maximum`, and `default`. `query`, `body`, and `path_params` objects are still accepted. A documented header such as `x-upsert` is an argument named `x_upsert` and is sent as that header on the downstream `tools/call`. `company_id` and staff-only `scheduled_job_run_id` are not arguments. Approval follows upstream `x-mcp` `read_only` and `destructive`. PATCH is a write, not a destructive call, unless `x-mcp.destructive` says so.

`ai_search_tools` returns compact rows: `name`, a one-line `description`, `read_only`, `destructive`, and `needs_approval`. `ai_describe_tool` returns a trimmed schema for those names. Descriptions are shortened and each schema stays inside a small character budget so a chat client can keep the result in the conversation.

Enum values on a parameter are copied from the service OpenAPI schema onto that named argument. `GET /api/v1/templates` in email-service currently types `event_type` as a plain string, with no `enum` and no list of allowed values. The only sample in that document is the response example `identity.auth.magic_link.requested`, which is not the query contract. Email-service needs to publish the allowed event names on that query parameter (`schema.enum`, or a description that lists them). This gateway will show them as soon as they are on the OpenAPI schema. It does not invent the list.

**LiteLLM** or other inference stacks are **not** part of this gateway path; this document covers the gateway only.

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

The **same** signing material is used for other internal Identity calls (**revocation poll** and **approval** assertions). If signing is not configured, **revocation polling fails closed** (treat as blocked). See `apps/connector/mcp_identity.py`. Tool-call logs are stored in this service and are not sent to Identity.

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
  "instruction": "This link is for the human user. Show it to them verbatim as a clickable link. Do not open, fetch, or sign in to it yourself. After they say they approved <tool>, call this tool again with the same arguments."
}
```

The text content starts with `Approval pending.` and includes the same JSON. `_meta.shellui_approval` repeats `approval_id`, `status`, `expires_at`, `approval_url`, and the settings list URL. Calling the same tool again with the same arguments after the person approves consumes the grant and runs the tool **once**. A second replay, a denial, or an expiry returns a clear message and does not run the tool.

`approval_url` is absolute. Identity `develop` at `d9539a7540f535c30bcbc4f70472e68d0edeb541` (PR **#149**) returns it on create and on state, on the public issuer (`JWT_ISSUER` / `IDENTITY_ISSUER`). The page is `GET /oauth/mcp/approval/<uuid>?token=<signed>`. The gateway uses that `approval_url` as sent. If a response omits it, the gateway joins the public issuer to `fallback_path` (the same path and token, relative). If that path is also absent, it builds `{issuer}/oauth/mcp/approval/{approval_id}`.

**Approval channels.** The channel is chosen per tool, then limited by what the negotiated protocol can actually deliver.

Destructive tools (`destructiveHint`, registry `_meta.destructive`, or `DELETE`) always use the approval link. A company can force the link for every other tool with `MCP_APPROVAL_CHANNEL_BY_COMPANY` (JSON map of company id to `form` or `link`). That setting cannot turn a destructive tool into an in-chat approval. Identity has no per-company approval-channel field, so this override is gateway configuration.

Form elicitation is used only when the client declared form mode and the negotiated revision can carry it:

- `2025-11-25` and `2025-06-18`: the `tools/call` POST is answered as `text/event-stream`. The first SSE event is a server request, `elicitation/create` (form Approve/Deny, or URL mode for link-channel approvals). The client posts the JSON-RPC result back on the same session. The gateway then finishes that tool call on the same stream. Hermes uses this path. Its default `protocol: auto` completes the legacy `initialize` handshake, so it lands on `2025-06-18` / `2025-11-25` and never reads `resultType: input_required`.
- `2026-07-28` only: `resultType: input_required` with `inputResponses` on the retry. This gateway does not negotiate that revision, so it does not send form `input_required` for in-chat Approve/Deny. URL-capable clients that cannot hold SSE still receive URL mode as `input_required` on the pending link result.
- Anything else, or a client that does not accept `text/event-stream`: the link text below.

The stream stays open for `MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS` (default 90). That stays under `GUNICORN_TIMEOUT` (default 120) so the worker can still write the link fallback. The wait is shared through the Django cache, so a multi-worker deployment needs `REDIS_URL`. If the client does not answer in time, or the stream cannot be held, the `tools/call` result is the link text. `accept` (including an empty `content` object, which is what Hermes sends for Yes) records `decision: allow` with `consent: in_chat` and runs the tool once. `decline` records `decision: deny` and does not run the tool. `cancel` does not decide; the result is the link text and the approval stays pending.

For form Approve/Deny cards, the elicitation `message` includes the approval URL as a fallback. The pending tool result always puts that URL in the plain text `content` as well as in `structuredContent.approval_url`.

**Link-channel elicitation (destructive tools, or company `link` override).** When the client accepts SSE on `2025-06-18` / `2025-11-25`, the gateway **holds the `tools/call` open** and polls Identity until the human decides on the approval page (or the wait times out). After Approve, it consumes the grant and finishes that same tool call — the person does not need to say “I approved” in chat.

- Clients that declared URL elicitation (`capabilities.elicitation.url`) also get `elicitation/create` with `mode: url` (one-click Open). The message does **not** repeat the URL; the gateway holds and polls until the browser decides.
- Form-only clients (including Cursor today) get an **immediate pending tool result** with the raw approval URL in plain text / `structuredContent.approval_url` — no form Submit card (that cannot open the browser). The human opens the link; the agent retries after approval (or polls `ai_get_approval`).
- Without SSE: URL-capable clients may still see URL mode as `input_required` on the pending result; otherwise the pending link text is returned immediately.
- Dismissing or declining a URL elicitation does **not** decide the approval and does **not** end the wait early.

Timeout falls back to the same pending link text as before.

The link text is in the plain `content` text and in `structuredContent`. It tells the agent the link is for the human, to show it verbatim as a clickable link, not to open, fetch, or sign in, and to call the same tool again with the same arguments after the person says they approved.

A retry with the same agent, tool, and arguments hash reuses the pending approval. The gateway does not create another row while Identity still reports that binding as `pending`.

In-chat consent trusts the MCP client. The gateway does not see a separate human gesture. On Approve it calls `mcp-approval-decide` with `decision: allow`, `consent: in_chat`, and `client_name` (the MCP `clientInfo.name`, collapsed, at most 80 characters). On Deny it sends `decision: deny` with the same consent fields. Identity PR **#150** stores those optional fields. Until it is deployed, a 400 that names `consent` or `client_name` is retried once without them so the decision still completes. `consent: in_chat` on a destructive row is not sent. If Identity returns 409 for that case, the tool does not run.

`params._meta.shellui_approval.decision` of `allow` or `session_allow` is ignored. An agent cannot approve itself, including for destructive tools. `deny` is still honored. An `approval_id` in that block is only a correlation hint. Approval otherwise comes from the identity page, admin, or a real elicitation response for a non-destructive tool. **Approval-gated retries** must replay the **full** tool call (same export name and normalized arguments). Changing the action or normalized args requires a **new** approval.

Form elicitation on `2025-06-18` (non-destructive, client declared form elicitation, `Accept` includes `text/event-stream`):

```json
{
  "jsonrpc": "2.0",
  "id": "<rpc id>",
  "method": "elicitation/create",
  "params": {
    "mode": "form",
    "message": "Allow storage_create_bucket? Choose Approve or Deny. This link is for the human user: https://identity.example/oauth/mcp/approval/<id>. Show it verbatim as a clickable link. Do not open, fetch, or sign in to it yourself.",
    "requestedSchema": {
      "type": "object",
      "properties": {
        "decision": {
          "type": "string",
          "title": "Decision",
          "enum": ["approve", "deny"],
          "enumNames": ["Approve", "Deny"]
        }
      },
      "required": ["decision"]
    }
  }
}
```

### URL elicitation

URL mode is `capabilities.elicitation.url` as an object (MCP spec 2025-11-25). An empty `elicitation` object is form mode only. Hermes declines URL-mode elicitations and does not declare `url`, so destructive approvals stay on the pending link text. Every other agent that declares `url` receives `mode: url` for link-channel approvals (SSE `elicitation/create`, or `input_required` when the session cannot stream). The elicitation `message` does not embed the URL; the `url` field carries it. The pending tool result still includes the human link in plain text and `structuredContent.approval_url`. A later retry that carries `inputResponses.approval.action` of `decline` or `cancel` does not run the tool. `accept` on that retry still waits for Identity to report the row approved before the tool runs.

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

## Call logs

ai-service stores one row in `McpCallLog` for every gateway `tools/call`. That includes direct remote tools, `ai_call_tool` (one row with the inner tool name and wrapper `ai_call_tool`), discovery tools (`ai_list_services`, `ai_search_tools`, `ai_describe_tool`, `ai_get_approval`, and a failed `ai_call_tool`), approval waiting, denied, and accepted on the form and link channels, and upstream errors and timeouts. A write failure is logged and does not fail the tool call.

The gateway does not POST tool-call logs to Identity `POST /api/v1/mcp/internal/mcp-call-logs`. Revocation polling, delegated-authority checks, and approval requests still use Identity. Those are not tool-call logs.

### Company admin list

`GET /ai/v1/mcp/call-logs`

Authentication is a bearer JWT verified the same way as other ai-service APIs. The caller must be staff, a company owner, or a company admin for the `company_id` on that JWT. A company admin is `user_metadata.is_company_admin`, or a group named `admin`, `admins`, or `company admins`, and does not have to be an owner. A plain member cannot read the list. A token cannot read another company. Agent access tokens are refused.

| Parameter | Meaning |
| --- | --- |
| `agent` | Exact agent id |
| `service` | `identity`, `storage`, `hosting`, `email`, `saas`, or `ai` |
| `tool` | Exact tool name |
| `status` | `allowed`, `denied`, `waiting_approval`, `failed`, or `error` |
| `created_after` | Inclusive ISO-8601 datetime |
| `created_before` | Exclusive ISO-8601 datetime |
| `limit` | Page size, 1 to 200, default 50 |
| `offset` | Rows to skip, default 0 |

```json
{
  "count": 1,
  "limit": 50,
  "offset": 0,
  "call_logs": [
    {
      "id": 1,
      "company_id": 10,
      "agent_id": "agent-id",
      "agent_name": "Example agent",
      "client_id": "",
      "client_name": "",
      "token_kind": "agent",
      "user_id": null,
      "user_email": "",
      "service": "storage",
      "tool_name": "storage_list_buckets",
      "wrapper_tool": "",
      "operation_title": "storage_list_buckets",
      "access_kind": "read",
      "outcome": "allowed",
      "resource_label": "storage_list_buckets",
      "arguments": {},
      "status": "allowed",
      "status_code": 200,
      "error_code": "",
      "error_message": "",
      "duration_ms": 12,
      "approval_id": "",
      "approval_channel": "none",
      "approval_outcome": "",
      "created_at": "2026-11-11T00:00:00+00:00"
    }
  ]
}
```

`token_kind` is `delegated`, `personal`, or `agent`. `approval_channel` is `form`, `link`, or `none`. `failed` means the tool ran and reported an error. `error` means the gateway could not finish the call (timeout or upstream outage). `outcome` is the display label: `allowed`, `failed`, `denied`, `waiting_approval`, or `session_used`. `access_kind` is `read`, `write`, or `destructive` from registry flags or the gateway classification, otherwise `unknown`. `operation_title` falls back to the tool name. `resource_label` is the audit label, or the tool name when that label is empty.

When the agent token carries `global_agent_id` or `global_company_id`, the row also includes `agent_audit_scope` (`global_company`), `global_agent_id`, and `global_company_id`.

Arguments go through `redact_arguments` before insert. Secret-shaped fields are stored as `***`.

Retention is `MCP_CALL_LOG_RETENTION_DAYS` (default 90). `python manage.py prune_mcp_call_logs` deletes older rows.

### Safe metadata

Approval creates still must not send `arguments` or `arguments_redacted`. A redacted `arguments_summary` string (max 500 characters) is the only argument text Identity accepts, and only on that create.

A downstream HTTP 2xx alone does not imply `allowed` if the gateway classified the operation as an error (`is_error`, audit `log_result`). See `outcome_from_audit`.

### Approvals: state before create, retry, and bodies

On each gated **`tools/call`**, the gateway calls **`mcp-approval-state`** first (empty JSON body; binding is **only** in the signed assertion). Identity **200** is always `id`, `status` (`pending`, `approved`, `denied`, or `expired`), `expires_at`, `is_destructive`, and absolute `approval_url`. `404` means no row. The `id` is kept for every status so a pending or approved row is not created again.

- **Create** (`mcp-approval-requests`): JSON body is `is_destructive` (boolean) and, when there is a safe redacted preview, `arguments_summary` (string, at most 500 characters). Identity stores that summary on `short_action_summary` and shows it on the approval page. Never send `arguments`, `arguments_redacted`, `target`, `short_action_summary`, `path`, or `method`.
- **State** (`mcp-approval-state`): empty JSON body. Use the returned `approval_url` and `expires_at`.
- **Decide** (`mcp-approval-decide`): includes `approval_id`, `decision`, sanitized `connection_id`, optional `actor_email`.
- **Consume** (`mcp-approval-consume`): JSON **`{ "approval_id": "…" }`** only.

See **`test_mcp_identity_conformance`** for a mocked Identity round-trip (state → pending → allow → consume) that asserts those body shapes.

### Coordinator: sibling services (storage / hosting / email)

Other service gateways that write MCP approvals should match the same approval contract: **no** `arguments` or `arguments_redacted` on approval creates; binding only in signed assertions; **live** delegated-authority checks where applicable. Tool calls made through this gateway are logged here. storage-service, hosting-service, and email-service still forward their own MCP calls to Identity ingest, and identity-service still writes a local call log for tools invoked on identity itself. Follow-up changes in those repositories should stop sending tool-call copies to Identity so this list stays the only copy.

## Client conformance and CI

- **Conformance and audits:** [mcp-e2e-conformance.md](./mcp-e2e-conformance.md), [mcp-tool-schema-audit.md](./mcp-tool-schema-audit.md).
- **MCP e2e scope:** the `tools/mcp-e2e` compose stack leaves storage, hosting, and email URLs empty by default and uses a **SaaS mock**. See [mcp-e2e-conformance.md](./mcp-e2e-conformance.md). You may set `STORAGE_SERVICE_URL`, `HOSTING_SERVICE_URL`, `EMAIL_SERVICE_URL`, or `SAAS_SERVICE_URL` in the environment before `docker compose` for local full-path checks. Do not treat a green **MCP client conformance** job as full-stack or regional-delegated-downstream proof unless CI is extended and you document the refs you pinned.
- **CI** checks out **`shellui/identity-service`** at **`develop`** by default unless the repository variable **`IDENTITY_SERVICE_REF`** is set (branch name or full SHA). To align with **identity PR #135** while it is open, pin that PR’s **current** `headRefOid` from GitHub (it moves with pushes). Record the **exact ref you validated** in the **pull request description** for traceability.

## Unsupported / transport notes

- **`resources/`** and **`templates/`** are not used as generic MCP transports here; tool responses follow the **text** / structured content patterns enforced by the Django MCP integration.
- Downstream adapters must treat broker and HTTP errors as **untrusted** for user-visible text; the gateway redacts and maps to allowlisted **error_code** values where applicable.
