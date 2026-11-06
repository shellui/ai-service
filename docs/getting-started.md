---
title: Getting started
---

# Getting started

For the full Shellui stack (identity, storage, and siblings), see [Shellui local dev stack](./devstack.md).

```bash
cp .env.example .env
docker compose up --build
```

Health: `GET http://localhost:8006/ai/v1/health`

MCP: `POST http://localhost:8006/c/<company_id>/mcp` with a Bearer agent token from identity OAuth.
