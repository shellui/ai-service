"""Company display name resolution for MCP tool titles."""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings

from apps.connector.agent_record import AgentRecord
from apps.connector.mcp_company_label import resolve_company_label
from apps.connector.mcp_tenant import company_label_from_claims


class CompanyLabelFromClaimsTests(SimpleTestCase):
    def test_prefers_name_in_token(self):
        self.assertEqual(
            company_label_from_claims({'company_id': 3, 'company_name': 'Acme'}),
            'Acme',
        )


@override_settings(
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-company-label-tests',
        }
    }
)
class ResolveCompanyLabelTests(TestCase):
    def setUp(self):
        cache.clear()

    @patch('apps.connector.mcp_company_label.fetch_company_name_from_identity', return_value='Acme Corp')
    def test_resolve_fetches_when_token_only_has_company_id(self, fetch):
        agent = AgentRecord(agent_id='agent-1', company_id=10, services_allowed=['ai', 'identity'])
        label = resolve_company_label({'company_id': 10, 'agent_id': 'agent-1'}, agent=agent)
        self.assertEqual(label, 'Acme Corp')
        fetch.assert_called_once()
        self.assertEqual(resolve_company_label({'company_id': 10, 'agent_id': 'agent-1'}, agent=agent), 'Acme Corp')

    def test_resolve_keeps_claim_name_without_fetch(self):
        agent = AgentRecord(agent_id='agent-1', company_id=10, services_allowed=['ai'])
        label = resolve_company_label(
            {'company_id': 10, 'company_name': 'Acme'},
            agent=agent,
        )
        self.assertEqual(label, 'Acme')
