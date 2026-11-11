"""Redis/local wake for MCP approval decisions + internal notify endpoint."""

from __future__ import annotations

import json
import threading
import time
from unittest.mock import patch

import jwt
from django.core.cache import cache
from django.test import Client, SimpleTestCase, TestCase, override_settings

from apps.connector.mcp_approval_events import (
    publish_approval_decision,
    wait_approval_decision,
)
from apps.connector.mcp_views import _ai_get_approval_sse_stream

_SECRET = 'test-hs256-secret-for-mcp-approval-decided'  # gitleaks:allow


@override_settings(
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-approval-events',
        }
    },
    REDIS_URL='',
)
class McpApprovalEventsTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def test_publish_wakes_local_waiter(self):
        seen: list[str | None] = []

        def waiter():
            seen.append(wait_approval_decision('appr-wake', timeout_seconds=2.0))

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.05)
        publish_approval_decision('appr-wake', 'approved')
        thread.join(timeout=2.0)
        self.assertEqual(seen, ['approved'])

    def test_wait_returns_cached_decision_immediately(self):
        publish_approval_decision('appr-cached', 'denied')
        self.assertEqual(wait_approval_decision('appr-cached', timeout_seconds=0), 'denied')

    def test_timeout_fallback_returns_none_without_decision(self):
        self.assertIsNone(wait_approval_decision('appr-missing', timeout_seconds=0.05))

    def test_link_hold_timeout_falls_back_to_identity_state(self):
        from apps.connector.mcp_form_elicitation import wait_for_link_page_approval

        reads: list[str] = []

        def approval_state(_p):
            reads.append('read')
            return 'approved' if len(reads) > 1 else 'pending'

        decided = wait_for_link_page_approval(
            approval_payload={'approval_id': 'appr-timeout'},
            timeout_seconds=0.05,
            approval_state=approval_state,
            wait_decision=lambda *_a, **_k: None,
        )
        self.assertEqual(decided, 'approved')
        self.assertEqual(len(reads), 2)


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET=_SECRET,
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-approval-decided-http',
        }
    },
    REDIS_URL='',
)
class McpApprovalDecidedEndpointTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()

    def _token(self, *, approval_id='appr-1', status='approved') -> str:
        now = int(time.time())
        return jwt.encode(
            {
                'iss': 'https://identity.test',
                'aud': 'shellui-mcp-approval-decided',
                'sub': 'identity',
                'scope': 'mcp.approval.decided',
                'approval_id': approval_id,
                'status': status,
                'company_id': 10,
                'agent_id': 'a1',
                'iat': now,
                'exp': now + 60,
            },
            _SECRET,
            algorithm='HS256',
        )

    @patch('apps.connector.mcp_approval_decided_views.get_jwks_client')
    def test_internal_endpoint_publishes(self, get_jwks):
        get_jwks.return_value.get_signing_key.return_value = None
        response = self.client.post(
            '/internal/mcp-approval-decided',
            data=json.dumps({'approval_id': 'appr-1', 'status': 'approved', 'company_id': 10, 'agent_id': 'a1'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._token()}',
        )
        self.assertEqual(response.status_code, 204)
        self.assertEqual(wait_approval_decision('appr-1', timeout_seconds=0), 'approved')

    @patch('apps.connector.mcp_approval_decided_views.get_jwks_client')
    def test_internal_endpoint_unauthorized_without_token(self, get_jwks):
        get_jwks.return_value.get_signing_key.return_value = None
        response = self.client.post(
            '/internal/mcp-approval-decided',
            data=json.dumps({'approval_id': 'appr-1', 'status': 'approved'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 401)


@override_settings(
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-mcp-approval-sse',
        }
    },
    REDIS_URL='',
)
class AiGetApprovalSseTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def test_sse_stream_returns_approved_after_publish(self):
        claims = {'agent_id': 'a1', 'company_id': 10}

        def status_for_agent(approval_id, _agent_claims):
            known = wait_approval_decision(approval_id, timeout_seconds=0)
            if known:
                return {'status': known, 'approval_id': approval_id, 'tool': 'storage_create_bucket'}
            return {'status': 'pending', 'approval_id': approval_id, 'tool': 'storage_create_bucket'}

        def publisher():
            time.sleep(0.05)
            publish_approval_decision('appr-sse', 'approved')

        with patch('apps.connector.mcp_approvals.approval_status_for_agent', status_for_agent):
            thread = threading.Thread(target=publisher)
            thread.start()
            chunks = list(
                _ai_get_approval_sse_stream(
                    req_id=7,
                    approval_id='appr-sse',
                    agent_claims=claims,
                    timeout_seconds=2.0,
                    keepalive_seconds=1.0,
                )
            )
            thread.join(timeout=2.0)
        joined = ''.join(chunks)
        self.assertIn('event: message', joined)
        self.assertIn('"id": 7', joined)
        self.assertIn('approved', joined)
        data_line = next(line for line in joined.splitlines() if line.startswith('data: '))
        payload = json.loads(data_line[len('data: ') :])
        body = json.loads(payload['result']['content'][0]['text'])
        self.assertEqual(body['status'], 'approved')
