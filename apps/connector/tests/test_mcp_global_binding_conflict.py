"""Partial global triple rejects all internal MCP approval paths (identity #135)."""

from __future__ import annotations

import time
from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.connector import mcp_approvals
from apps.connector.mcp_setup_context import approval_assertion_context_from_agent_claims

_GV = 1
_CBV = 1
_GLOBAL_CO = '11111111-1111-4111-8111-111111111111'


@override_settings(
    AI_SERVICE_ISSUER='https://ai.test',
    IDENTITY_ISSUER='https://identity.test',
)
class GlobalBindingConflictTests(TestCase):
    def test_partial_grant_version_only_blocks_assertion(self):
        now = int(time.time())
        ctx = approval_assertion_context_from_agent_claims(
            {'iat': now, 'exp': now + 3600, 'grant_version': _GV},
        )
        self.assertTrue(ctx.blocked_assertion)

    @patch('apps.connector.mcp_approvals.requests.post')
    def test_create_skipped_when_partial_triple(self, post):
        payload = {
            'agent_id': 'a1',
            'company_id': 10,
            'service': 'storage',
            'action': 'x',
            'arguments_hash': 'h' * 64,
            '_agent_claims': {
                'iat': int(time.time()),
                'exp': int(time.time()) + 3600,
                'grant_version': _GV,
            },
        }
        self.assertIsNone(mcp_approvals.create_approval_request(payload))
        post.assert_not_called()
