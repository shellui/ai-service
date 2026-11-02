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
