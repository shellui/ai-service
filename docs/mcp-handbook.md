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

Forwarded to Identity as canonical **`outcome`** values: **`pending_approval`**, **`allowed`**, **`denied`**, **`failed`**, **`session_used`**.  
`decide` responses that surface Identity’s human **`status`: `approved`** map to audit token **`identity_approved`** → outcome **`allowed`** (so they are not misclassified as failure when `audit_status` differs). **`error_code`** is allowlisted (`mcp_audit_codes.py`), including **`mcp_tool_error`** for safe tool-registry failures.

## Revocation cache

The gateway polls Identity’s signed revocation list and caches it for a **short TTL** (on the order of **~30 seconds** per server defaults). Revocations are **not** guaranteed instant in every process; treat the cache as **fail-closed** when the list cannot be fetched.

## CI: Identity revision

Optional Actions variable **`IDENTITY_SERVICE_REF`** selects the `shellui/identity-service` ref for MCP tooling in CI (see `.github/workflows/ci.yml`).

## Further reading

- Product / integration guide: **#180** (link in your internal docs index when available).
- Identity PR **#135** — authority snapshots, `grant_version` / `global_company_id` / `company_binding_version`, and stricter parsers (source of truth for assertion contracts).
