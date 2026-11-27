"""Tests for first-run superuser bootstrap gating at GET/POST /."""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

User = get_user_model()

VALID_POST = {
    'username': 'admin',
    'email': 'admin@example.com',
    'password': 'long-enough-passphrase',
    'password_confirm': 'long-enough-passphrase',
}


@override_settings(ALLOWED_HOSTS=['testserver'])
class BootstrapDebugTests(TestCase):
    """DEBUG=true still requires SETUP_TOKEN before the form creates a superuser."""

    def setUp(self):
        self.client = Client()

    @override_settings(DEBUG=True, SETUP_TOKEN='')
    def test_get_hides_form_without_token(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create superuser')
        self.assertContains(response, 'createsuperuser')

    @override_settings(DEBUG=True, SETUP_TOKEN='')
    def test_post_returns_403_without_token(self):
        response = self.client.post('/', VALID_POST)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())

    @override_settings(DEBUG=True, SETUP_TOKEN='s3tup-token-for-tests-0123456789abcdefXYZ')
    def test_post_returns_403_with_wrong_token(self):
        data = {**VALID_POST, 'setup_token': 'wrong-token-wrong-token-wrong-token-0000'}
        response = self.client.post('/', data)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())

    @override_settings(DEBUG=True, SETUP_TOKEN='s3tup-token-for-tests-0123456789abcdefXYZ')
    def test_post_creates_superuser_with_token(self):
        data = {**VALID_POST, 'setup_token': 's3tup-token-for-tests-0123456789abcdefXYZ'}
        response = self.client.post('/', data)
        self.assertRedirects(response, '/?setup=done', fetch_redirect_response=False)
        user = User.objects.get(username='admin')
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

        response = self.client.get('/')
        self.assertNotContains(response, 'Create superuser')

    @override_settings(DEBUG=True, SETUP_TOKEN='s3tup-token-for-tests-0123456789abcdefXYZ')
    def test_post_with_existing_user_redirects_without_creating(self):
        User.objects.create_superuser(username='existing', email='', password='long-enough-passphrase')
        before = User.objects.count()
        data = {**VALID_POST, 'setup_token': 's3tup-token-for-tests-0123456789abcdefXYZ'}
        response = self.client.post('/', data)
        self.assertRedirects(response, '/', fetch_redirect_response=False)
        self.assertEqual(User.objects.count(), before)

    @override_settings(DEBUG=True, SETUP_TOKEN='s3tup-token-for-tests-0123456789abcdefXYZ')
    def test_password_mismatch_shows_error(self):
        data = {**VALID_POST, 'password_confirm': 'different-passphrase', 'setup_token': 's3tup-token-for-tests-0123456789abcdefXYZ'}
        response = self.client.post('/', data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Passwords do not match.')
        self.assertFalse(User.objects.exists())


@override_settings(ALLOWED_HOSTS=['testserver'], DEBUG=False, SETUP_TOKEN='')
class BootstrapProductionBlockedTests(TestCase):
    """Production-like settings block public bootstrap without a token."""

    def setUp(self):
        self.client = Client()

    def test_get_hides_form_when_no_users(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create superuser')
        self.assertContains(response, 'createsuperuser')

    def test_post_returns_403_without_token(self):
        response = self.client.post('/', VALID_POST)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())

    def test_get_with_users_shows_docs_only(self):
        User.objects.create_superuser(username='existing', email='', password='long-enough-passphrase')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create superuser')
        self.assertNotContains(response, 'createsuperuser')


@override_settings(ALLOWED_HOSTS=['testserver'], DEBUG=False, SETUP_TOKEN='s3tup-token-for-tests-0123456789abcdefXYZ')
class BootstrapSetupTokenTests(TestCase):
    """SETUP_TOKEN enables one-time web bootstrap when DEBUG=false."""

    def setUp(self):
        self.client = Client()

    def test_get_shows_the_form_with_a_token_field_and_no_secret(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create superuser')
        self.assertContains(response, 'name="setup_token"')
        self.assertNotContains(response, 's3tup-token-for-tests-0123456789abcdefXYZ')

    def test_query_token_does_not_authorise_a_post(self):
        response = self.client.post('/?setup_token=s3tup-token-for-tests-0123456789abcdefXYZ', VALID_POST)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())

    def test_header_token_on_a_get_does_not_change_the_page(self):
        response = self.client.get('/', HTTP_X_SETUP_TOKEN='wrong-token-wrong-token-wrong-token-0000')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 's3tup-token-for-tests-0123456789abcdefXYZ')

    def test_post_creates_superuser_with_body_token(self):
        data = {**VALID_POST, 'setup_token': 's3tup-token-for-tests-0123456789abcdefXYZ'}
        response = self.client.post('/', data)
        self.assertRedirects(response, '/?setup=done', fetch_redirect_response=False)
        self.assertTrue(User.objects.filter(username='admin', is_superuser=True).exists())

    def test_post_creates_superuser_with_header_token(self):
        response = self.client.post(
            '/',
            VALID_POST,
            HTTP_X_SETUP_TOKEN='s3tup-token-for-tests-0123456789abcdefXYZ',
        )
        self.assertRedirects(response, '/?setup=done', fetch_redirect_response=False)
        self.assertTrue(User.objects.filter(username='admin', is_superuser=True).exists())

    def test_post_returns_403_with_wrong_token(self):
        data = {**VALID_POST, 'setup_token': 'wrong-token-wrong-token-wrong-token-0000'}
        response = self.client.post('/', data)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())


@override_settings(ALLOWED_HOSTS=['testserver'], DEBUG=False, SETUP_TOKEN='too-short-token')
class BootstrapShortTokenTests(TestCase):
    """A token under 32 characters is never accepted."""

    def test_short_token_is_refused_in_the_header_and_the_body(self):
        client = Client()
        response = client.post('/', VALID_POST, HTTP_X_SETUP_TOKEN='too-short-token')
        self.assertEqual(response.status_code, 403)
        response = client.post('/', {**VALID_POST, 'setup_token': 'too-short-token'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.exists())

    def test_short_token_hides_the_form(self):
        response = Client().get('/')
        self.assertNotContains(response, 'Create superuser')
