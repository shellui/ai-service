# ai-service

Shellui AI service: single MCP connector for all Shellui services.

- **MCP:** `POST /c/<company_id>/mcp` (one URL per company; aggregated tools across identity, storage, hosting, email, SaaS).
- **OAuth metadata:** `GET /.well-known/oauth-protected-resource/c/<company_id>/mcp` (authorization server is identity-service).
- **Health:** `GET /ai/v1/health` and `GET /health/live`.

Python 3.14, Django 6, `shellui-django[mcp]==0.3.0`. See [docs/](docs/) and [PUBLISH.md](PUBLISH.md).

## Run locally

The recommended way is the Shellui dev stack. It runs this service with every other Shellui service and front-end in Docker, with your checkout mounted for hot reload. Clone the Shellui repos side by side, then:

```bash
cd shellui/dev
./start.sh
```

ai is on [http://localhost:8006](http://localhost:8006). See the [Shellui dev stack guide](https://github.com/shellui/shellui/blob/develop/docs/dev-stack.md) and [docs/devstack.md](docs/devstack.md) for notes specific to this service.
