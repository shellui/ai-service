"""AgentRecord.from_claims: scope vs persisted services_allowed."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.connector.agent_record import AgentRecord


class AgentRecordFromClaimsTests(SimpleTestCase):
    def test_scope_only_uses_scope(self):
        claims = {
            'agent_id': 'a1',
            'company_id': 1,
            'scope': 'ai storage',
        }
        rec = AgentRecord.from_claims(claims)
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertEqual(rec.services_allowed, ['ai', 'storage'])

    def test_intersects_when_services_allowed_present(self):
        """Broad OAuth ``scope`` must not widen persisted downstream grants."""
        claims = {
            'agent_id': 'a1',
            'company_id': 1,
            'scope': 'ai identity saas storage',
            'services_allowed': ['ai', 'identity'],
        }
        rec = AgentRecord.from_claims(claims)
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertEqual(rec.services_allowed, ['ai', 'identity'])

    def test_legacy_services_alias(self):
        claims = {
            'agent_id': 'a1',
            'company_id': 1,
            'scope': 'ai email',
            'services': ['ai'],
        }
        rec = AgentRecord.from_claims(claims)
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertEqual(rec.services_allowed, ['ai'])

    def test_empty_intersection_yields_no_services(self):
        claims = {
            'agent_id': 'a1',
            'company_id': 1,
            'scope': 'ai',
            'services_allowed': ['storage'],
        }
        rec = AgentRecord.from_claims(claims)
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertEqual(rec.services_allowed, [])
