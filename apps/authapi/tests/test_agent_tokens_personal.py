"""Personal MCP agent bearer tokens on the ai gateway."""

from __future__ import annotations

import time

import jwt
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

AI_MCP_1 = 'https://ai.test/c/1/mcp'
AI_MCP_2 = 'https://ai.test/c/2/mcp'
MCP_ACCEPT = 'application/json, text/event-stream'


def _rpc(method: str, **params):
    import json

    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})


def _token(*, secret: str, issuer: str, resource: str, company_id: int, personal: bool) -> str:
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': 'agent:personal-a',
        'agent_id': 'personal-a',
        'company_id': company_id,
        'scope': 'ai identity',
        'mcp_access': 'read_only',
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'aud': resource,
        'iss': issuer,
        'iat': now,
        'exp': now + 3600,
    }
    if personal:
        claims['personal_token_id'] = '11111111-1111-1111-1111-111111111111'
        claims['jti'] = 'jti-personal-abc'
    return jwt.encode(claims, secret, algorithm='HS256')


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',
    IDENTITY_ISSUER='https://identity.test',
    AI_PUBLIC_URL='https://ai.test',
    AUTH_RATE_LIMIT_ENABLED=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'personal-mcp'}},
)
class PersonalAgentTokenGatewayTests(TestCase):
    def setUp(self):
        cache.clear()
        revoked = __import__('unittest.mock', fromlist=['patch']).patch(
            'apps.connector.mcp_views.agent_is_revoked', return_value=False
        )
        revoked.start()
        self.addCleanup(revoked.stop)
        unavailable = __import__('unittest.mock', fromlist=['patch']).patch(
            'apps.connector.mcp_views.identity_revocation_unavailable', return_value=False
        )
        unavailable.start()
        self.addCleanup(unavailable.stop)
        self.client = Client()
        self.secret = 'test-hs256-secret-for-mcp-gateway-tests-only'
        self.issuer = 'https://identity.test'

    def test_personal_token_works_on_matching_company_url(self):
        token = _token(
            secret=self.secret,
            issuer=self.issuer,
            resource=AI_MCP_1,
            company_id=1,
            personal=True,
        )
        response = self.client.post(
            '/c/1/mcp',
            data=_rpc('initialize', protocolVersion='2024-11-05', capabilities={}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_ACCEPT=MCP_ACCEPT,
        )
        self.assertEqual(response.status_code, 200)

    def test_personal_token_rejected_without_jti(self):
        token = _token(
            secret=self.secret,
            issuer=self.issuer,
            resource=AI_MCP_1,
            company_id=1,
            personal=True,
        )
        payload = jwt.decode(token, self.secret, algorithms=['HS256'], options={'verify_signature': False})
        del payload['jti']
        bad = jwt.encode(payload, self.secret, algorithm='HS256')
        response = self.client.post(
            '/c/1/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {bad}',
            HTTP_ACCEPT=MCP_ACCEPT,
        )
        self.assertEqual(response.status_code, 401)

    def test_company_1_token_fails_on_company_2_url(self):
        token = _token(
            secret=self.secret,
            issuer=self.issuer,
            resource=AI_MCP_1,
            company_id=1,
            personal=True,
        )
        response = self.client.post(
            '/c/2/mcp',
            data=_rpc('tools/list'),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_ACCEPT=MCP_ACCEPT,
        )
        self.assertEqual(response.status_code, 401)
