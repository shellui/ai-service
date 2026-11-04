# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] - 2026-11-04

### 🛠 Improvements

- MCP gateway exports stable ``service_verb_noun`` tool names with titles, descriptions, field help, and MCP annotations on every ``tools/list`` entry.

### ✨ Feature

- MCP OAuth protected-resource metadata advertises `shellui_mcp_authorize_query` (`saas_offered=1`) when SaaS tools are forwarded; e2e OAuth clients append it on authorize.
- Personal MCP agent RS256 bearer tokens (identity personal flow) on `POST /c/<company_id>/mcp` with JWKS verification, `aud` / `company_id` binding, revocation polling, and `personal_token_id` + `jti` honored.
- MCP call logs to identity include `client_ip` and `result`; arguments and secrets are never forwarded.

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

## [0.1.0] - 2026-11-02

### ✨ Feature

- Docker `dev` target and devstack env documentation for the Shellui local compose stack.
- Bootstrap ai-service on Django 6 and Python 3.14 with sibling CI, Docker, and docs layout.
- Aggregated MCP gateway at `POST /mcp` using `shellui-django[mcp]==0.3.0` (`AggregatingMcpServer`).
- OAuth protected-resource metadata pointing authorization to identity-service.
- Agent JWT verification via identity JWKS, revocation polling, and MCP call log forwarding.
- Downstream service discovery from `IDENTITY`, `STORAGE`, `HOSTING`, `EMAIL`, and `SAAS` service URL settings.
- Reserved `apps.keys` package for future model API key storage.
- RS256 delegation JWTs for identity downstream MCP access-token minting (`AI_SERVICE_SIGNING_KEY`, `AI_SERVICE_SIGNING_KID`, `AI_SERVICE_ISSUER`).
- Public JWKS at `GET /.well-known/jwks.json` and `python manage.py generate_signing_key` for operators.
- Pre-release Docker smoke generates ephemeral RS256 signing material (same pattern as smoke JWKS).
- Bump `shellui-django[mcp]` to 0.4.0 and sign internal MCP assertions to identity (revocation polling, call logs) with `AI_SERVICE_SIGNING_KEY` and `AI_SERVICE_ISSUER`, failing closed when unset.

### 🛠 Improvements

- CI MCP client conformance job (`tools/mcp-e2e/run.sh`): identity + ai stack, official TypeScript and Python MCP SDK OAuth flows, MCP Inspector CLI `tools/list`, form-urlencoded token exchange, negative OAuth/tenant checks, and strict MCP tool `inputSchema` audit.
- MCP tool `inputSchema` builder copies typed OpenAPI query/body fields (resolves `$ref`) and normalizes aggregated tools for strict clients; same change belongs in `shellui-django` 0.4.1 (`django-commons`).

### 🐛 Bug Fixes

- MCP gateway `initialize` responses now include `serverInfo` and negotiate `protocolVersion` per the 2025-06-18 spec (workaround for `shellui-django` 0.4.0 omitting `serverInfo`); Streamable HTTP accepts `notifications/initialized` with `202`, validates `Accept` and `MCP-Protocol-Version`, issues `Mcp-Session-Id`, and paginates `tools/list`.
- Gateway tests in `apps/connector` now run in CI (the package was missing `__init__.py`).
- The MCP gateway is served per company at `/c/<company_id>/mcp`, with matching protected-resource metadata; tokens must name that company, plain `/mcp` returns 404 `company_required`, and every downstream tool carries its service prefix (`storage__…`).
- MCP gateway asks identity for downstream tokens bound to each service's public resource (`*_SERVICE_PUBLIC_URL`), not the internal URL it calls.
