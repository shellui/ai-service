---
title: MCP gateway backend handbook
---

# MCP gateway backend handbook

Backend reference for **`POST /c/<company_id>/mcp`** in ai-service. For the shorter overview see [mcp.md](./mcp.md); for conformance runs see [mcp-e2e-conformance.md](./mcp-e2e-conformance.md).

## Endpoint and OAuth

- **MCP (JSON-RPC):** `POST /c/<company_id>/mcp` — `company_id` is the **regional** integer tenant in the path and in the agent JWT `company_id` claim.
- **Protected resource metadata (RFC 9728):** `GET /.well-known/oauth-protected-resource/c/<company_id>/mcp`.
- **Token mint (region identity):** use your **regional** identity issuer’s **`POST .../oauth/token`** (OAuth2) with the correct `resource` / audience for the company-scoped MCP URL—not a legacy generic “/mcp/token” shortcut. The gateway only verifies agents against the URL-named company.

### Delegation and global binding (identity #135 alignment)

Regional agent JWTs may carry:

- **`global_company_id`**: canonical UUID string (only with delegation).
- **`grant_version`**, **`company_binding_version`**: JSON **integers** (≥ 0); **bool and numeric strings are rejected** in gateway parsing.

The gateway treats **partial** triples as **`blocked_assertion`**: no signed internal approval calls. The **full triple** is required for delegated global flows. **`personal_token_id`** alone does not imply delegation.

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

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }
```

### `tools/call` (storage — names are gateway exports)

After `tools/list`, call a tool by its **full export name** (service prefix + OpenAPI-derived slug), e.g. **`storage_list_buckets`**. Arguments follow the tool `inputSchema` (path, method, query, body) produced from the service OpenAPI registry—not arbitrary client paths:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "storage_list_buckets",
    "arguments": {
      "path": "/api/v1/buckets/",
      "method": "GET",
      "query": {}
    }
  }
}
```

The gateway resolves **`name`** against its **cached tools/list catalog** and **route table**. Approval decisions and audits use **registry `_meta.method`** and **`_meta.path`** only; client-supplied `path`/`method` inside `arguments` are **not** trusted for activity metadata.

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
