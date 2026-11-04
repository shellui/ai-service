---
title: MCP gateway
---

# MCP gateway

See `POST /mcp` and `GET /.well-known/oauth-protected-resource`.

When the gateway calls a downstream service `/mcp`, it asks identity to mint a short-lived agent access token. ai-service signs that request with its own RS256 key (`shellui_django.mcp.delegation.sign_downstream_token_request`), not identity’s `SECRET_KEY`:

- Configure `AI_SERVICE_SIGNING_KEY` (or `AI_SERVICE_SIGNING_KEY_FILE`), `AI_SERVICE_SIGNING_KID`, and `AI_SERVICE_ISSUER`.
- Publish the public key at `GET /.well-known/jwks.json`.
- Generate keys: `python manage.py generate_signing_key` (or `--shell` for eval-friendly exports).

The same key signs internal assertions to identity (revocation polling and call logs, `shellui-django` 0.4.0+). Identity trusts them only from the issuer in its `AI_SERVICE_ISSUER` and verifies them with this JWKS. Without a signing key, revocation polling fails closed (every agent is treated as revoked) and call logs are skipped.

Identity endpoint: `POST /api/v1/mcp/internal/mcp-downstream-access-token`. It validates the bearer JWT using ai-service JWKS and `AI_SERVICE_ISSUER`, then returns `{ "access_token": "…" }`.
