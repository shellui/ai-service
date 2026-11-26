---
title: Connect an agent with device login
---

# Connect an agent with device login

Headless MCP clients (a CLI, or an agent such as Hermes) connect to a company with the [OAuth 2.0 device authorization grant](https://www.rfc-editor.org/rfc/rfc8628). The person sees a link and a code, approves on Identity, and the client polls until it receives tokens. Do not paste an access token, refresh token, device code, or user code into an agent chat.

This walkthrough uses the local stack: Identity at `http://localhost:8001`, ai-service at `http://localhost:8006`. Company `1` is the seeded dev company. See [Local dev stack](./devstack.md).

## What the client discovers

1. `POST http://localhost:8006/c/1/mcp` with no token (a `GET` of that URL does the same) returns **401** and:

```http
WWW-Authenticate: Bearer realm="mcp", resource_metadata="http://localhost:8006/.well-known/oauth-protected-resource/c/1/mcp", scope="mcp"
```

2. These URLs return the same protected-resource document (RFC 9728 path insertion, plus the suffix some clients append to the MCP path):

- `GET http://localhost:8006/.well-known/oauth-protected-resource/c/1/mcp`
- `GET http://localhost:8006/.well-known/oauth-protected-resource/c/1/mcp/`
- `GET http://localhost:8006/c/1/mcp/.well-known/oauth-protected-resource`

`GET http://localhost:8006/.well-known/oauth-protected-resource` stays **404** `company_required`. That URL has no company, and the gateway does not pick one.

3. The document looks like this. `authorization_servers` is exactly Identity's metadata `issuer` (`IDENTITY_ISSUER`, `http://localhost:8001` in the local stack). It is not the in-cluster `IDENTITY_SERVICE_URL`. There is no `device_authorization_endpoint` here.

```json
{
  "resource": "http://localhost:8006/c/1/mcp",
  "authorization_servers": ["http://localhost:8001"],
  "scopes_supported": ["mcp"],
  "bearer_methods_supported": ["header"]
}
```

4. `GET http://localhost:8001/.well-known/oauth-authorization-server` lists `device_authorization_endpoint`, `token_endpoint`, and the device-code grant. The client registers if it needs a `client_id`, requests a device code, shows the link and the user code, and polls.

`/c/0/mcp` and other non-companies stay **404** with no `WWW-Authenticate` header.

## Curl

```bash
export IDENTITY=http://localhost:8001
export MCP_URL=http://localhost:8006/c/1/mcp

curl -sS -D - -o /dev/null -X POST "$MCP_URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

curl -sS "$IDENTITY/.well-known/oauth-authorization-server"

curl -sS -X POST "$IDENTITY/oauth/mcp/register" \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"local-cli","redirect_uris":["http://127.0.0.1/callback"]}'
```

Keep `client_id` from the registration response.

```bash
export CLIENT_ID=the-client-id

curl -sS -X POST "$IDENTITY/oauth/mcp/device/code" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "resource=${MCP_URL}"
```

Open `verification_uri_complete` in a browser (or open `verification_uri` and type the user code). Sign in as a member of that company and choose **Allow**. Staff accounts cannot approve.

Poll about every `interval` seconds. `authorization_pending` means wait. `slow_down` means wait longer. `access_denied` and `expired_token` mean stop.

```bash
curl -sS -X POST "$IDENTITY/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "device_code=${DEVICE_CODE}" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "resource=${MCP_URL}"
```

A success body has `access_token` and `refresh_token`. The access token is the same shape as an authorization-code agent token: `aud` is the company MCP URL, `sub` is `agent:<uuid>`, and the claims include `agent_id`, `company_id`, `mcp_access`, `mcp_read`, `mcp_destructive`, `scope`, and `grant_version`. The gateway accepts it on `POST /c/<company_id>/mcp` the same way.

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Keep that token in the client. Do not paste it into chat. A static personal token, if you still use one, stays an advanced fallback outside this flow.

## Global MCP (Shellui account)

The global endpoint `https://ai.shellui.com/mcp` has no company in the path. ai-service in global mode is its own authorization server. Sign-in goes through identity-global, and consent is on ai-service.

1. Any method on `/mcp` without a token (`GET`, `POST` or `DELETE`) returns **401** and:

```http
WWW-Authenticate: Bearer realm="shellui", resource_metadata="https://ai.shellui.com/.well-known/oauth-protected-resource", scope="mcp"
```

A request with a token that does not verify gets the same header plus `error="invalid_token"`.

2. `GET https://ai.shellui.com/.well-known/oauth-authorization-server` lists `device_authorization_endpoint` (`/oauth/mcp/device/code`) and `urn:ietf:params:oauth:grant-type:device_code` in `grant_types_supported`.

3. Register. Browser clients send loopback redirect URIs: `http://127.0.0.1`, `http://localhost` or `http://[::1]` on any port are accepted in every environment, as on Identity. A client that only uses device login can send `"grant_types": ["urn:ietf:params:oauth:grant-type:device_code"]` and no `redirect_uris`.

```bash
export AI=https://ai.shellui.com

curl -sS -X POST "$AI/oauth/mcp/register" \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"my-cli","grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}'

curl -sS -X POST "$AI/oauth/mcp/device/code" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "scope=mcp"
```

The response has `device_code`, `user_code` (`XXXX-XXXX`), `verification_uri` (`$AI/oauth/mcp/device`), `verification_uri_complete`, `expires_in` (600) and `interval` (5).

4. The person opens the link, signs in with their Shellui account, and sees the consent page. It shows the client name exactly as registered, a warning that the client chose that name itself, and the access requested. Staff accounts and accounts that have not accepted the terms are refused.

5. Poll the token endpoint with the device code. Errors follow RFC 8628: `authorization_pending`, `slow_down` (the interval grows by 5 seconds each time), `access_denied`, `expired_token`. A device code works once. A second exchange returns `invalid_grant`.

```bash
curl -sS -X POST "$AI/oauth/mcp/token" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "device_code=${DEVICE_CODE}" \
  --data-urlencode "client_id=${CLIENT_ID}"
```

Success returns `access_token` (audience `https://ai.shellui.com/mcp`, scope `mcp`) and a rotating `refresh_token`, the same as the browser flow.

Rate limits per client IP: 30 device code requests per hour and 30 code entries per 10 minutes on the verification page.

Default `tools/list` on this endpoint is the account discovery set: `ai_search_tools`, `ai_describe_tool`, `ai_call_tool`, `ai_list_companies`, `ai_wait_for_company`, `ai_company_search_tools`, `ai_company_describe_tool`, `ai_call_company_tool`, `ai_grant_company_access`, and `ai_revoke_company_access`. Pass `{"mode": "all"}` to include SaaS account tools. The list does not include `ai_get_approval`. When a write needs approval, the original `tools/call` can wait over SSE, or the agent shows the approval link and retries the same tool after the person approves.

### Project access

Project tools (identity, storage, hosting, email) live on each project. Call `ai_list_companies`, then `ai_company_search_tools`, `ai_company_describe_tool` or `ai_call_company_tool` with the project `company_id`. `ai_search_tools` on the global endpoint only lists account tools, and its response carries a `project_tools` hint that says so.

The first project call opens access to a project the signed-in account belongs to, with no approval page:

- Membership is read from saas-service on every project call, with a saas token minted for the connection's own account. The client only sends `company_id`. A project of another account returns "Project was not found."
- The automatic grant is `ask`: read and write tools run, destructive tools still return an approval link. `allow_destructive` is always off on an automatic grant, and a `read_only` connection stays `read_only`.
- Region identity checks the membership again during the token exchange, refuses staff accounts, and caps the agent at the person's own rights in that project. Each regional token is bound to one project and one binding version.
- `ai_grant_company_access` narrows access at once (for example `access_mode: read_only`). Fields left out keep the current grant. Only an owner can widen, through an approval link.
- `ai_revoke_company_access` revokes access to one project. A revoked project is not granted again automatically; an owner grants it again with an approval link.
- Removing the person from the project in saas-service stops access on the next call.

## Active connections on the dashboard

The signed-in Shellui account lists and revokes its global MCP agents (device grants and browser OAuth grants) with an identity-global access token (`aud` is `GLOBAL_IDENTITY_AUDIENCE`, typically `shellui`). Results are limited to that account's subject. A token for another account cannot list or revoke these rows.

```
GET  /ai/v1/mcp/global/agents
POST /ai/v1/mcp/global/agents/{agent_id}/revoke
```

The response uses the same agent object as identity-service personal agents (`id`, `kind`, `name`, `access_mode`, `read_level`, `is_active`, `revoked_at`, `oauth_client_id`).

Each connection covers every project it has opened, including the automatic grants above. Revoking the connection also revokes all of its project grants and asks saas-service to push the revoke to each region.
