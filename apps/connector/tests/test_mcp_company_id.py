"""Strict regional company_id parsing (reject UUID-as-tenant confusion)."""

from __future__ import annotations

import uuid

from django.test import SimpleTestCase

from apps.connector.mcp_company_id import strict_numeric_company_id


class StrictNumericCompanyIdTests(SimpleTestCase):
    def test_positive_integer_string(self):
        self.assertEqual(strict_numeric_company_id('42'), 42)

    def test_int_pass_through(self):
        self.assertEqual(strict_numeric_company_id(7), 7)

    def test_uuid_string_rejected(self):
        self.assertIsNone(strict_numeric_company_id(str(uuid.uuid4())))

    def test_none_rejected(self):
        self.assertIsNone(strict_numeric_company_id(None))

    def test_non_numeric_string_rejected(self):
        self.assertIsNone(strict_numeric_company_id('acme'))
