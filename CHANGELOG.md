# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

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
