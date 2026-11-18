# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

<!---
## [Unreleased] - yyyy-mm-dd

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

### 📚 Documentation

- Publish a Docker Hub overview for `shellui/ai-service` with the release image.

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
