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
