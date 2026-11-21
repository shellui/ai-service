# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

<!---
### ✨ Feature - for new features
### 🛠 Improvements - for general improvements
### 🚨 Changed - for changes in existing functionality
### ⚠️ Deprecated - for soon-to-be removed features
### 📚 Documentation - for documentation update
### 🗑 Removed - for removed features
### 🐛 Bug Fixes - for any bug fixes
### 🔒 Security - in case of vulnerabilities
### 🏗 Chore - for tidying code

See for sample https://raw.githubusercontent.com/favoloso/conventional-changelog-emoji/master/CHANGELOG.md
-->

## [Unreleased]

### 🚨 Changed

- Global mode sends a regional subject token only to hosts in `REGIONAL_EXCHANGE_ALLOWED_HOSTS`. The default is empty, so no host is called until the list is set. With `DEBUG=false` the URL must be `https`. A suffix (`.shellui.com` or `*.shellui.com`) matches that domain and its subdomains. Token exchange does not follow redirects.
- SaaS tool path parameters are percent-encoded. A tool call whose URL leaves `SAAS_SERVICE_URL` or the OpenAPI path template is refused.
- The form at `/` requires `SETUP_TOKEN` when `DEBUG=true`, the same as when `DEBUG=false`. Leave `SETUP_TOKEN` empty and use `manage.py createsuperuser` for local setup.
- Published images build the Dockerfile `production` stage (`DEBUG=false`). The `dev` stage is local only and is not published. Root Compose tags that stage `ai-service:local`.
- `shellui-django[mcp]` is `0.6.0`. The gateway verifies the bearer token itself. Downstream calls for a tool the gateway already allowed send `mcp_gateway_delegated` as `{"action": "<tool name>", "exp": <unix seconds>}` on the bearer token, with `exp` 60 seconds ahead. Identity JWKS URLs must be `https` unless `DEBUG=true`, and redirects are not followed.

## [0.2.0] - 2026-11-18

### ✨ Feature

- `AI_SERVICE_MODE=global` serves MCP at `/mcp` with no company in the path. `region` stays the default and still serves `/c/<company_id>/mcp`.
- Global mode is an OAuth authorization server: discovery, dynamic client registration, PKCE, server-rendered consent, and rotating refresh tokens (30 days).
- Global sign-in uses identity-global. The browser is sent to `{GLOBAL_IDENTITY_URL}/oauth/authorize`, and the code is redeemed at `{GLOBAL_IDENTITY_INTERNAL_URL}/oauth/token`.
- Global mode loads SaaS tools from OpenAPI `x-mcp` and calls them over REST. Reads follow the grant read level. Writes ask in chat.
- `ai_list_companies` and `ai_wait_for_company` list projects and wait for provisioning. `ai_company_search_tools`, `ai_company_describe_tool`, and `ai_call_company_tool` forward to that project's regional gateway.
- `ai_grant_company_access` lets an owner grant one project. A new or wider grant opens an approval link. Narrowing the grant, or `ai_revoke_company_access`, bumps `binding_version` and calls saas to fan out the revoke.
- A regional approval comes back as the regional link, or the same form. The form answer is posted to the company gateway with `X-Shellui-Correlation-Id`.
- Call logs record `plane` (`global` or `region`), `owner_sub`, and `correlation_id`. Global rows may omit `company_id`. The regional gateway stores `X-Shellui-Correlation-Id` when the caller token is global delegated.

### 🚨 Changed

- Breaking: region mode ignores `SAAS_SERVICE_URL` and no longer forwards SaaS tools. OAuth metadata on the region gateway no longer includes `saas_offered`.
- Breaking: boot checks refuse mixed settings. Region mode must leave `GLOBAL_IDENTITY_URL`, `GLOBAL_OIDC_CLIENT_ID`, `GLOBAL_OIDC_CLIENT_SECRET`, and `SAAS_API_AUDIENCE` unset. Global mode must leave `IDENTITY_JWKS`, `IDENTITY_JWKS_FILE`, `IDENTITY_JWKS_URL`, `IDENTITY_SERVICE_URL`, `IDENTITY_ISSUER`, `IDENTITY_AUDIENCE`, `STORAGE_SERVICE_URL`, `HOSTING_SERVICE_URL`, and `EMAIL_SERVICE_API_KEY` unset.
- Breaking: with `DEBUG=false`, global mode requires `GLOBAL_IDENTITY_URL`, `GLOBAL_IDENTITY_ISSUER`, `GLOBAL_IDENTITY_JWKS` or `GLOBAL_IDENTITY_JWKS_URL`, `GLOBAL_OIDC_CLIENT_ID`, `GLOBAL_OIDC_CLIENT_SECRET`, `GLOBAL_OIDC_REDIRECT_URI`, `SAAS_SERVICE_URL`, and `SAAS_API_AUDIENCE`, plus `AI_SERVICE_SIGNING_KEY` (or `AI_SERVICE_SIGNING_KEY_FILE`), `AI_SERVICE_SIGNING_KID`, and `AI_SERVICE_ISSUER`. Region URLs come from saas `GET /regions`.
- Dependabot opens version-update pull requests against `develop`.

### 🐛 Bug Fixes

- Docker Hub overview updates sign in with `DOCKERHUB_DESCRIPTION_USERNAME` and `DOCKERHUB_DESCRIPTION_TOKEN`. Use a personal access token with Read, Write, and Delete, from a user with Admin on `shellui/ai-service`. Image push still uses `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Publish skips the overview step when those secrets are empty, so a missing token does not fail the release.

### 🔒 Security

- Staff accounts cannot authorize a global MCP agent. Accept the Shellui terms before connecting an agent.
- A regional access token sent to global `/mcp` is rejected. The error names the regional company MCP URL.
- Global MCP refuses project deletion. Destructive calls that are allowed use an approval link, not a form.
- Global access tokens, saas API tokens, and subject tokens for regional exchange are signed with `AI_SERVICE_SIGNING_KEY`. The public key stays at `GET /.well-known/jwks.json`. Refresh tokens rotate.

### 📚 Documentation

- The Docker Hub overview and the configuration reference describe region mode and global mode, including the dev-stack environment names for the global container.

## [0.1.0] - 2026-11-18

### ✨ Feature

- Shellui MCP gateway for a company at `/c/<company_id>/mcp`, with OAuth metadata pointed at identity-service.
- The gateway discovers storage, hosting, email, identity, and SaaS tools and calls them with delegated agent tokens.
- `tools/list` returns a short discovery set, including `ai_search_tools` and `ai_call_tool`, instead of every downstream tool.
- Staff, company owners, and company admins can list MCP tool-call logs at `GET /ai/v1/mcp/call-logs`.
- A member can list call logs for an agent they own at `GET /ai/v1/mcp/personal/agents/{agent_id}/call-logs`.
- Company MCP OAuth discovery supports the device authorization grant for headless clients.
- Personal MCP agent tokens are accepted on the company MCP URL, with JWKS checks and revocation polling.
- OAuth metadata includes `saas_offered=1` when the gateway forwards SaaS tools.
- Operators can generate an RS256 signing key and publish JWKS at `GET /.well-known/jwks.json`.
- Low-risk tool calls can be approved in chat when the client supports form elicitation. Destructive tool calls use an approval link.
- `tools/call` returns the approval link immediately. `ai_get_approval` resumes when the approval is allowed or denied.
- A denied approval, or an expired grant for the same arguments, opens a new approval.

### 🛠 Improvements

- Published tool names are stable `service_verb_noun` names, with titles, descriptions, field help, and MCP annotations.
- Tool titles lead with the Shellui service name and the connected company display name.
- Tool input schemas copy typed OpenAPI fields, including `$ref` bodies, and drop transport arguments such as method and path.
- Documented request headers such as `Idempotency-Key` are tool arguments. `Authorization` stays off the schema.
- `tools/call` accepts legacy Hermes argument envelopes. `ai_describe_tool` keeps heavy body fields such as `document`.
- CI runs MCP client conformance against the official TypeScript and Python SDKs.
- Docker dev target and dev-stack environment docs for the Shellui local compose stack.

### 📚 Documentation

- MCP handbooks document the published tool names and the discovery list.
- Publish a Docker Hub overview for `shellui/ai-service` with the release image.

### 🐛 Bug Fixes

- `initialize` includes `serverInfo`, negotiates the protocol version, issues a session id, and paginates `tools/list`.
- `tools/call` rebuilds downstream routes when the route cache expires, so legacy slugs and published names still run.
- The gateway asks identity for tokens bound to each service's public MCP URL, not the internal URL it calls.
- Personal regional agents with a valid grant can open and consume approvals. Incomplete or invalid authority claims stay blocked.
- Call logs include measured duration. Arguments and secrets are never stored.
- A session approval does not run a destructive tool.
- API reference pages render in Shellui Admin when the Shellui SDK does not finish loading.
- The Docker dev image skips ownership changes when the app user is missing.
- The home page and error pages describe the Shellui MCP gateway.

### 🔒 Security

- `tools/list` does not expose company id on tool inputs. `tools/call` binds the company from the agent token and rejects cross-company overrides.
- Agent tokens are limited by `mcp_access` and `mcp_destructive` before a tool runs.
- Destructive tool calls require approval, including when the agent token is `mcp_access=full`.
- Internal assertions to identity are signed with this service's RS256 key, use the identity issuer as the audience, and fail closed when the key is unset.
- Old call-log rows are pruned after 90 days by default.

### 🗑 Removed

- The gateway no longer forwards tool-call logs to identity. ai-service stores them itself.
