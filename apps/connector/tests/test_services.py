from django.test import SimpleTestCase, override_settings

from apps.connector.services import configured_service_urls, list_mcp_services


@override_settings(
    IDENTITY_SERVICE_URL='https://identity.test',
    STORAGE_SERVICE_URL='https://storage.test',
    HOSTING_SERVICE_URL='',
    EMAIL_SERVICE_URL='https://email.test',
    EMAIL_SERVICE_API_KEY='',
    SAAS_SERVICE_URL='https://saas.test',
)
class ServiceDiscoveryTests(SimpleTestCase):
    def test_list_mcp_services_uses_settings_only(self):
        services = list_mcp_services()
        ids = {item['id'] for item in services}
        self.assertIn('identity', ids)
        self.assertIn('storage', ids)
        self.assertIn('saas', ids)
        self.assertNotIn('email', ids)
        urls = configured_service_urls()
        self.assertEqual(urls['storage'], 'https://storage.test/mcp')


@override_settings(
    IDENTITY_SERVICE_URL='http://identity:8000',
    IDENTITY_ISSUER='http://localhost:8001',
    STORAGE_SERVICE_URL='http://storage:8000',
    STORAGE_SERVICE_PUBLIC_URL='http://localhost:8002',
    HOSTING_SERVICE_URL='https://hosting.test',
    HOSTING_SERVICE_PUBLIC_URL=None,
    EMAIL_SERVICE_URL='',
    SAAS_SERVICE_URL='',
)
class DownstreamResourceTests(SimpleTestCase):
    """Tokens are minted for the public resource even when the gateway calls an internal URL."""

    def test_internal_url_maps_to_public_resource(self):
        from apps.connector.services import downstream_resource_for

        self.assertEqual(downstream_resource_for('http://storage:8000/mcp'), 'http://localhost:8002/mcp')
        self.assertEqual(downstream_resource_for('http://identity:8000/mcp'), 'http://localhost:8001/mcp')

    def test_without_public_url_resource_is_the_service_url(self):
        from apps.connector.services import downstream_resource_for

        self.assertEqual(downstream_resource_for('https://hosting.test/mcp'), 'https://hosting.test/mcp')

    def test_unknown_url_has_no_resource_and_mint_is_refused(self):
        from unittest.mock import patch

        from apps.connector import mcp_views
        from apps.connector.downstream_tokens import DownstreamTokenError
        from apps.connector.services import downstream_resource_for

        self.assertIsNone(downstream_resource_for('http://evil.test/mcp'))
        with patch.object(mcp_views, 'mint_downstream_access_token') as mint:
            with self.assertRaises(DownstreamTokenError):
                mcp_views._mint_token(object(), 'http://evil.test/mcp')
            mint.assert_not_called()
            mcp_views._mint_token(object(), 'http://storage:8000/mcp')
            self.assertEqual(mint.call_args.kwargs['resource'], 'http://localhost:8002/mcp')
