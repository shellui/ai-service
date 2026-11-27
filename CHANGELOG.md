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

- `shellui-django` 0.8.0 with Django 6.1.3, Django REST framework 3.18.3 and drf-spectacular 0.30.0. The shellui-django pins are exact, so these move together.
- gunicorn 27.0.1. A request whose `Transfer-Encoding` does not end with `chunked` (for example `identity` alone) now gets HTTP 400. No gunicorn setting changed.
- Django 6.1 requires PostgreSQL 15 or newer, and drops 14. Check the database of any deployment before upgrading. CI and the MCP end to end compose file run PostgreSQL 18.
- drf-spectacular 0.30 describes blank URL and slug fields as `oneOf` (the field's format or an empty string) in the OpenAPI schema. Generated clients and the published schema see that change. The API itself does not change.

### 🔒 Security

- Django 6.1.3 includes the Django security releases of October and November 2026, among them a fix for memory use when parsing large multipart uploads.

### 🏗 Chore

- Node.js 26, the current LTS, for the image build stage and CI.
- GitHub Actions: actions/checkout v7, actions/setup-node v7, astral-sh/setup-uv v10.4.0, docker/build-push-action v7, docker/login-action v4, docker/metadata-action v6, docker/setup-buildx-action v4, docker/setup-qemu-action v4, peter-evans/dockerhub-description v5.0.0.
- Python dependencies: python-dotenv 1.2.4, psycopg 3.3.9, sentry-sdk 2.77.0, cryptography 50.0.2, requests 2.34.2, markdown 3.11.4, redis 8.2.0, sqlparse 0.6.1.
- npm dependencies: @tailwindcss/cli 4.3.5, tailwindcss 4.3.5.
- CI runs `manage.py makemigrations --check --dry-run`, so a model change without a migration fails the build.
- CI pins Python 3.14.10 and uv 0.13.10, and the Dockerfile copies the same uv, so CI and the image run the same interpreter and the same tool.

## [0.4.2] - 2026-11-27

### 🐛 Bug Fixes

- Global MCP `tools/list` no longer advertises `ai_get_approval`. That tool is handled only on the regional company endpoint. On the global endpoint, agents learn the outcome from the approval link, the original call's SSE wait, or by retrying the same tool after approval.
- Approval messages for project tools relayed through `ai_call_company_tool` no longer tell the agent to call `ai_get_approval` on the global endpoint. They tell the agent to show the approval link and retry the same `ai_call_company_tool` call after approval.

## [0.4.1] - 2026-11-26

### 🐛 Bug Fixes

- Global MCP can reach regions that share its host. `GLOBAL_REGION_INTERNAL_URLS` maps a region's public origin to an internal one for the token exchange and regional MCP calls. The MCP `resource` and token audiences keep the public URL.

## [0.4.0] - 2026-11-25

### ✨ Feature

- Global MCP opens a project the signed-in account belongs to on first use, with no approval page. Membership is checked on saas-service with the connection's own account on every call. The automatic grant is `ask`: read and write tools run, destructive tools still ask.
- `ai_search_tools` on the global endpoint returns a `project_tools` hint that points at `ai_list_companies` and `ai_company_search_tools`.

### 🚨 Changed

- Project members can narrow or revoke their own connection on a project. Widening still needs an owner and an approval link. Fields left out of `ai_grant_company_access` keep the current grant.

### 🔒 Security

- Revoking a global connection also revokes its project grants and fans the revoke out to the regions.
- Cached regional tokens are keyed by binding version, so a narrowed grant never reuses an older token.

### 🐛 Bug Fixes

- Granting a project again after a revoke reuses the revoked row instead of failing on the unique constraint.

## [0.3.3] - 2026-11-25

### 🐛 Bug Fixes

- `ai_list_companies` accepts the JSON array returned by saas-service `GET /api/v1/companies` (and the `results` or `companies` wrappers). A 200 list was previously treated as a failure and surfaced as "Could not list projects."
- Company region parsing reads the saas `CompanySerializer` `region` string (for example `ch`) as well as a nested `{code, ai_url}` object, so project lists and grants keep the region code and AI URL.
- The empty `ai_search_tools` hint in global mode points at `ai_list_companies` instead of `ai_list_services`, which is not in the global tools list.

### ✨ Feature

- Dashboard connections API: `GET /ai/v1/mcp/global/agents` and `POST /ai/v1/mcp/global/agents/{id}/revoke`. Authenticated with the signed-in identity-global access JWT. Results and revoke are scoped to that subject only.

### 🔒 Security

- Added isolation tests with two users and two companies. MCP access tokens, saas API JWTs, and identity-global session JWTs use real RS256 shapes. User B cannot list user A's projects, grants, or connections, cannot call, describe, grant, or revoke tools on user A's company, and cannot revoke user A's agent. A token bound to one company fails on another.

## [0.3.2] - 2026-11-25

### 🐛 Bug Fixes

- Global MCP OIDC sign-in (`signin/complete`) verifies the opaque OIDC `access_token` against identity-global `/oauth/userinfo` instead of sending it to saas-service `/api/v1/me` (which requires a JWT and returned 401, falsely showing the regional-only error to Shellui account owners in both browser and device flows).
- `saas_client.fetch_me` accepts the `subject` key returned by saas-service `/api/v1/me` in addition to `sub` and `id`.
- `eligibility.terms_accepted` refuses only when a terms claim is present and falsy rather than blocking accounts when identity-global emits no terms claim.
- `?error=access_denied` on `signin/complete` renders a sign-in cancelled or staff-refused message instead of the regional-only message.
- Replaced the literal `https://<regional ai>/c/<company_id>/mcp` placeholder in the regional-only message with a pointer to the Shellui dashboard and docs.

### 🛠 Improvements

- Global MCP HTML pages (`consent`, `device_code`, `decision`, `message`) share a common base layout matching `identity-service` and Shellui design tokens (`static/css/site.css`, Shellui mark header, centered 480px card, warning box, stacked buttons, dark mode).

## [0.3.1] - 2026-11-25

### ✨ Feature

- Global MCP supports the OAuth 2.0 device authorization grant (RFC 8628). `POST /oauth/mcp/device/code` returns a device code, a user code (`XXXX-XXXX`), `verification_uri` (`/oauth/mcp/device`) and `verification_uri_complete`. The code lives 10 minutes, the poll interval starts at 5 seconds, and `slow_down` adds 5 seconds. Device codes and user codes are stored as hashes and work once. Sign-in uses identity-global, and approval creates the agent through the same consent as the browser flow.
- Authorization server metadata lists `device_authorization_endpoint` and the `urn:ietf:params:oauth:grant-type:device_code` grant.
- Dynamic client registration accepts a device-only client with no `redirect_uris` when `grant_types` has the device grant and not `authorization_code`.

### 🐛 Bug Fixes

- Global MCP client registration accepts loopback redirect URIs (`http://127.0.0.1`, `http://localhost`, `http://[::1]`, any port) in every environment, as Identity does. Before, it returned `400 invalid_redirect_uris` unless `DEBUG` was on, which blocked Cursor, Hermes, the MCP Inspector and the Python SDK. The unused `OAUTH_ALLOW_LOOPBACK_REDIRECTS` lookup is removed.
- `GET /mcp` without a token returns 401 with `WWW-Authenticate` instead of 405, like the regional gateway. The challenge includes `scope="mcp"` and leaves out the error code when no token was sent (RFC 6750 section 3.1).

### 🔒 Security

- Redirect URIs with a fragment or user info are refused.
- The consent page shows the client name exactly as registered, warns that Shellui does not verify it, and lists the access requested.
- Device code requests and code entry are rate limited per client IP.

### 📚 Documentation

- `docs/mcp-device-login.md` has a section for device login on global MCP.

## [0.3.0] - 2026-11-24

### ✨ Feature

- OpenTelemetry traces and metrics through `shellui-django[mcp,otel]==0.7.0`. Export stays off until `OTEL_EXPORTER_OTLP_ENDPOINT` is set. `service.name` defaults to `ai-service`, and `service.version` is the package version. The resource attribute `shellui.mode` is `region` or `global`.
- An MCP request records `mcp.method.name` and, for `tools/call`, `mcp.tool.name`. Tool arguments and results are not span attributes. Outbound `requests` calls, including the downstream gateway hop and identity downstream-token minting, continue the trace with W3C `traceparent`.
- Logs include `trace_id` and `span_id` next to the existing request id (`X-Request-ID`).

### 🚨 Changed

- Breaking: removed the unused `prometheus-client` dependency. `GET /metrics` and `GET /metrics/all` are not served (404). This service had no Prometheus metrics to port, and JSON stats routes were not part of this API.
- `pat_agm` is no longer copied onto the request principal as `access_global_metrics`. The claim only existed for Prometheus global metrics, and this service never authorized a route with it. No database column is dropped.

### 📚 Documentation

- Document `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_SERVICE_NAME`, and `OTEL_RESOURCE_ATTRIBUTES` (`deployment.environment`, `cloud.region`).

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
