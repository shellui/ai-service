"""Strict ``global_company_id`` parsing (delegated path)."""

from __future__ import annotations

import uuid

from django.test import SimpleTestCase

from apps.connector.mcp_setup_context import parse_global_company_id

_FIXED = '11111111-1111-4111-8111-111111111111'


class ParseGlobalCompanyIdTests(SimpleTestCase):
    def test_whitespace_uuid_string_canonicalizes(self):
        self.assertEqual(
            parse_global_company_id('  11111111-1111-4111-8111-111111111111  '),
            _FIXED,
        )

    def test_uuid_instance(self):
        self.assertEqual(parse_global_company_id(uuid.UUID(_FIXED)), _FIXED)

    def test_rejects_non_string_non_uuid(self):
        self.assertIsNone(parse_global_company_id({'not': 'a-uuid'}))
