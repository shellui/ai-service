---
title: Shellui AI service
description: Aggregated MCP connector for Shellui agents.
---

# Shellui AI service

ai-service hosts the single aggregated MCP gateway for Shellui (`POST /c/<company_id>/mcp`, one URL per company). OAuth protected-resource metadata points clients at identity-service. Headless agents connect with device login: a link and a code, then a poll. See [Device login](./mcp-device-login.md). Do not paste an access token into an agent chat.

Future releases will store company AI model API keys here. Version 0.1.0 ships MCP only.
