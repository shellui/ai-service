---
title: Getting started
---

# Getting started

```bash
cp .env.example .env
docker compose up --build
```

Health: `GET http://localhost:8003/ai/v1/health`

MCP: `POST http://localhost:8003/mcp` with a Bearer agent token from identity OAuth.
