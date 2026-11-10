---
title: MCP gateway backend handbook
---

# MCP gateway backend handbook

:::note

MCP is in Beta. Tool names and behavior may still change.

:::

Backend reference for **`POST /c/<company_id>/mcp`** in ai-service. For the shorter overview see [mcp.md](./mcp.md); for conformance runs see [mcp-e2e-conformance.md](./mcp-e2e-conformance.md).

## Endpoint and OAuth

- **MCP (JSON-RPC):** `POST /c/<company_id>/mcp` — `company_id` is the **regional** integer tenant in the path and in the agent JWT `company_id` claim.
- **Protected resource metadata (RFC 9728):** `GET /.well-known/oauth-protected-resource/c/<company_id>/mcp` and the same document at the trailing-slash and `/c/<company_id>/mcp/.well-known/oauth-protected-resource` paths. `authorization_servers` equals Identity's metadata `issuer` (`IDENTITY_ISSUER`). `scopes_supported` is `["mcp"]`. `bearer_methods_supported` is `["header"]`. Do not put `device_authorization_endpoint` on this document. The root `GET /.well-known/oauth-protected-resource` is `404` `company_required`.
- **401 challenge:** `WWW-Authenticate: Bearer realm="mcp", resource_metadata="<absolute URL of that document>", scope="mcp"` on every 401 from `POST` or `GET /c/<company_id>/mcp`. Non-positive company ids stay `404` without that header.
- **Token mint (region identity):** use your **regional** identity issuer’s **`POST .../oauth/token`** (OAuth2), including `grant_type=urn:ietf:params:oauth:grant-type:device_code`, with the correct `resource` / audience for the company-scoped MCP URL—not a legacy generic “/mcp/token” shortcut. The gateway only verifies agents against the URL-named company. A device-grant access token carries the same claims as an authorization-code token (`aud`, `sub` `agent:<uuid>`, `agent_id`, `company_id`, `mcp_access`, `mcp_read`, `mcp_destructive`, `scope`, `grant_version`) and is accepted the same way. Curl walkthrough: [mcp-device-login.md](./mcp-device-login.md).

### Delegation and global binding (identity #135 alignment)

Regional agent JWTs may carry:

- **`global_company_id`**: canonical UUID string (only with delegation).
- **`grant_version`**, **`company_binding_version`**: JSON **integers** (≥ 0); **bool and numeric strings are rejected** in gateway parsing.

A personal regional token may carry **`grant_version`** alone (no **`global_company_id`**, no **`company_binding_version`**, and **`mcp_authority`** not **`delegated`** or **`global_delegated`**). That is not a partial global binding: approval create, state, and consume still sign an assertion that includes **`grant_version`**. Any other partial triple (a global company id without both versions, **`company_binding_version`** without **`global_company_id`**, a malformed global company id, or **`mcp_authority`** **`delegated`** / **`global_delegated`** without the full triple) stays **`blocked_assertion`**: no signed internal approval calls. Invalid setup claims stay blocked. The **full triple** is required for delegated global flows. **`personal_token_id`** alone does not imply delegation.

Internal approval and session assertions are **RS256** JWTs (`AI_SERVICE_SIGNING_KEY`, `AI_SERVICE_ISSUER`); binding fields (`company_id`, `agent_id`, `service`, `action`, `arguments_hash`) live in those signed claims—**not** in untrusted JSON bodies.

### Live delegated binding (Identity internal, canonical)

For **global-delegated** regional tokens (full `global_company_id` + `grant_version` + `company_binding_version`), the gateway also calls Identity’s live row check—**not** revocation polling alone:

- **URL:** `POST /api/v1/mcp/internal/mcp-agent-delegated-authority` (spellings like `mcp-delegated-agent-authority` are **not** supported).
- **Authorization:** `Bearer` RS256 assertion with **`aud`:** `shellui-mcp-agent-delegated-authority`, **`scope`:** `mcp.agent.delegated.authority.read`, **`target`:** Identity issuer (same pattern as other internal MCP routes).
- **JSON body (exactly five keys):** `agent_id` (uuid string), `company_id` (positive int), `global_company_id` (uuid string), `grant_version`, `company_binding_version` (non-negative JSON integers). Unknown keys → **400** from Identity.

**200** responses use a **fixed 15-key** JSON object (Identity `d7fe351`+ `_delegated_authority_fixed_payload`): **`authorized`**, **`active`**, **`revoked`**, **`paused`**, **`agent_id`**, **`company_id`**, **`global_agent_id`**, **`global_company_id`**, **`grant_version`**, **`company_binding_version`**, **`access_mode`**, **`read_level`**, **`allow_destructive`**, **`services_allowed`**, **`revoked_at`**. Extra keys → the gateway rejects the body.

To count as **allow** here, Identity must return **`authorized`: true**, **`active`: true**, **`revoked`** / **`paused`** / **`allow_destructive`** each **false**, **`services_allowed`** a **sorted** list of strings (narrow list, not a global catch-all), binding fields matching the request, and well-typed **`access_mode`** / **`read_level`**. **`200`** with **`authorized`: false** (and typically **`active`: false**) is a valid **deny** from Identity—treated like non-200. Non-**200**, transport errors, or shape mismatch → fail closed (same as **403** / **404**).

## JSON-RPC examples

### `initialize`

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": { "elicitation": {} }
  }
}
```

### `notifications/initialized`

```json
{ "jsonrpc": "2.0", "method": "notifications/initialized" }
```

### `tools/list`

The default list is a discovery set: `ai_list_services`, `ai_search_tools`, `ai_describe_tool`, `ai_call_tool`, `ai_get_approval`, and four common reads when that service is connected (`identity_list_users`, `storage_list_bucket`, `hosting_list_apps`, `email_list_messages`). They answer "who, what files, what apps, what mail" without a search. `ai_get_approval` reads one pending approval by id and does not run the tool.

Ask for the full operational catalog with `POST /c/<company_id>/mcp?tools=all`, or `tools/list` params `{"tools": "all"}`. Set `MCP_TOOLS_LIST_MODE=all` when a deployment should keep the full list as the default. The full list is still paged (200 tools per page, `nextCursor`).

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }
```

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": { "tools": "all" } }
```

Example:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ai_search_tools","arguments":{"query":"invite a user","limit":3}}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ai_call_tool","arguments":{"name":"identity_create_invitations","arguments":{"email":"ada@example.com"}}}}
```

### `tools/call` (storage: names are gateway exports)

After `tools/list`, call a tool by its **full export name** (service prefix + OpenAPI-derived slug), for example **`storage_list_bucket`**. Arguments are the named fields from that tool's `inputSchema` (query, body, and path parameters flattened). Do not send HTTP `method` or `path`. The gateway fills those from the registry:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "storage_list_bucket",
    "arguments": {}
  }
}
```

The gateway resolves **`name`** against its **cached tools/list catalog** and **route table**. If the tools list has expired while the route key is still present, the gateway loads that service's catalog again and then forwards the call. Approval decisions and audits use **registry `_meta.method`** and **`_meta.path`** only. Client-supplied `path` and `method` are ignored.

Upstream may list the tool as the export name (`storage_list_bucket`, `identity_create_groups`), as `x-mcp.tool_name` without the service prefix (`list_apps`), or as a legacy operationId slug (`storage_v1_bucket_list`, `api_v1_groups_create`). All three produce the same gateway name. The service prefix is added once. The forwarded `tools/call` uses the upstream name.

## Internal Identity: `mcp-approval-requests` body

`create_approval_request` sends **only**:

```json
{ "is_destructive": true }
```

or

```json
{ "is_destructive": false }
```

Binding (`service`, `action` = export name, `arguments_hash`, company, agent) is carried **only** in the signed `Authorization` assertion JWT headers—never `arguments`, `path`, `method`, or `short_action_summary` in the POST JSON.

## Call log outcomes (activity)

Internal audit rows use **`outcome`** (`allowed`, `failed`, `denied`, `pending_approval`, `session_used`). **`forward_call_log`** maps to Identity **`develop`** canonical ingest (**`waiting_approval`** instead of **`pending_approval`**) and always reports the **wire** downstream call as **`POST /mcp`** with allowlisted **`error_code`** when needed. The POST body matches **`McpInternalCallLogView`** + **`canonical_call_path`** (required **`grant_version`** from JWT, optional delegated pair only when the JWT is delegated); see [mcp.md](./mcp.md) call logs section.

## Revocation cache

The gateway polls Identity’s signed revocation list and caches it for a **short TTL** (on the order of **~30 seconds** per server defaults). Revocations are **not** guaranteed instant in every process; treat the cache as **fail-closed** when the list cannot be fetched.

## CI: Identity revision

Optional Actions variable **`IDENTITY_SERVICE_REF`** selects the `shellui/identity-service` ref for MCP tooling in CI (see `.github/workflows/ci.yml`).

## Further reading

- Product / integration guide: **#180** (link in your internal docs index when available).
- Identity PR **#135** — authority snapshots, `grant_version` / `global_company_id` / `company_binding_version`, and stricter parsers (source of truth for assertion contracts).
