# ai-service

Shellui AI service: single MCP connector for all Shellui services.

- **MCP:** `POST /mcp` (aggregated tools across identity, storage, hosting, email, SaaS).
- **OAuth metadata:** `GET /.well-known/oauth-protected-resource` (authorization server is identity-service).
- **Health:** `GET /ai/v1/health` and `GET /health/live`.

Python 3.14, Django 6, `shellui-django[mcp]==0.3.0`. See [docs/](docs/) and [PUBLISH.md](PUBLISH.md).
