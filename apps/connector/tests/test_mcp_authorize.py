"""OAuth protected-resource metadata extensions (SaaS opt-in)."""

from __future__ import annotations

from django.test import Client, TestCase, override_settings

from apps.connector.mcp_authorize import SHELLUI_MCP_AUTHORIZE_QUERY_KEY


@override_settings(
    IDENTITY_ISSUER='https://identity.test',
    AI_PUBLIC_URL='https://ai.test',
    SAAS_SERVICE_URL='',
)
class McpOAuthMetadataTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_no_saas_extension_when_saas_not_configured(self):
        response = self.client.get('/.well-known/oauth-protected-resource/c/1/mcp')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertNotIn(SHELLUI_MCP_AUTHORIZE_QUERY_KEY, body)

    @override_settings(SAAS_SERVICE_URL='https://saas.test', SAAS_SERVICE_PUBLIC_URL='https://saas.test')
    def test_saas_offered_hint_when_saas_forwarded(self):
        response = self.client.get('/.well-known/oauth-protected-resource/c/1/mcp')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        ext = body.get(SHELLUI_MCP_AUTHORIZE_QUERY_KEY) or {}
        self.assertEqual(ext.get('saas_offered'), '1')
