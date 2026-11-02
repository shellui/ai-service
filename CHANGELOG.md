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

- Bootstrap ai-service on Django 6 and Python 3.14 with sibling CI, Docker, and docs layout.
- Aggregated MCP gateway at `POST /mcp` using `shellui-django[mcp]==0.2.0` (`AggregatingMcpServer`).
- OAuth protected-resource metadata pointing authorization to identity-service.
- Agent JWT verification via identity JWKS, revocation polling, and MCP call log forwarding.
- Downstream service discovery from `IDENTITY`, `STORAGE`, `HOSTING`, `EMAIL`, and `SAAS` service URL settings.
- Reserved `apps.keys` package for future model API key storage.
