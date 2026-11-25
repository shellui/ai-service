"""Loopback DCR without a toggle, RFC 8628 device login, and the GET /mcp challenge."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.global_mcp.device import normalize_user_code
from apps.global_mcp.models import GlobalAgentTokenAudit, McpDeviceAuthorization, OidcTransaction
from apps.global_mcp.tests.test_global_mode import GLOBAL, _profile

DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'


def _complete(state_value, code):
    row = OidcTransaction.objects.get(state=state_value)
    return row, {'sub': 'user-1', 'email': 'owner@example.com', 'access_token': 'unused'}


@override_settings(**GLOBAL)
class LoopbackRegistrationTests(TestCase):
    def setUp(self):
        cache.clear()

    def _register(self, uris, **extra):
        return self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'client_name': 'Probe', 'redirect_uris': uris, **extra}),
            content_type='application/json',
        )

    def test_loopback_http_is_allowed_with_debug_off(self):
        from django.conf import settings

        self.assertFalse(settings.DEBUG)
        self.assertFalse(hasattr(settings, 'OAUTH_ALLOW_LOOPBACK_REDIRECTS') and settings.OAUTH_ALLOW_LOOPBACK_REDIRECTS)
        for uri in (
            'http://127.0.0.1:33418/callback',
            'http://localhost:6274/oauth/callback',
            'http://[::1]:8080/cb',
            'http://127.0.0.1/callback',
            'https://app.example.com/cb',
            'cursor://anysphere.cursor-mcp/oauth/callback',
        ):
            with self.subTest(uri=uri):
                response = self._register([uri])
                self.assertEqual(response.status_code, 201, response.content)
                self.assertEqual(response.json()['redirect_uris'], [uri])

    def test_unsafe_redirects_are_refused(self):
        for uri in (
            'http://evil.example.com/cb',
            'http://127.0.0.1.evil.example.com/cb',
            'http://user@127.0.0.1:9/cb',
            'http://127.0.0.1:9/cb#frag',
            'javascript:alert(1)',
            '/relative',
        ):
            with self.subTest(uri=uri):
                response = self._register([uri])
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['error'], 'invalid_redirect_uris')

    def test_device_only_client_needs_no_redirect(self):
        self.assertEqual(self._register([]).status_code, 400)
        response = self._register([], grant_types=[DEVICE_GRANT, 'refresh_token'])
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()['grant_types'], [DEVICE_GRANT, 'refresh_token'])

    def test_authorize_with_loopback_reaches_sign_in(self):
        client_id = self._register(['http://127.0.0.1:33418/callback']).json()['client_id']
        response = self.client.get(
            '/oauth/mcp/authorize',
            {
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': 'http://127.0.0.1:33418/callback',
                'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                'code_challenge_method': 'S256',
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].startswith('http://id.test/oauth/authorize?'))


@override_settings(**GLOBAL)
class DeviceLoginTests(TestCase):
    def setUp(self):
        cache.clear()
        registered = self.client.post(
            '/oauth/mcp/register',
            data=json.dumps({'client_name': 'Hermes <Agent>', 'grant_types': [DEVICE_GRANT]}),
            content_type='application/json',
        )
        self.assertEqual(registered.status_code, 201, registered.content)
        self.client_id = registered.json()['client_id']

    def _start(self):
        response = self.client.post('/oauth/mcp/device/code', {'client_id': self.client_id, 'scope': 'mcp'})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response['Cache-Control'], 'no-store')
        return response.json()

    def _poll(self, device_code, *, reset=True):
        if reset:
            McpDeviceAuthorization.objects.update(last_poll_at=None)
        return self.client.post(
            '/oauth/mcp/token',
            {'grant_type': DEVICE_GRANT, 'device_code': device_code, 'client_id': self.client_id},
        )

    def _sign_in_and_open_consent(self, start):
        entered = self.client.get(start['verification_uri_complete'].replace('http://ai.test', ''))
        self.assertEqual(entered.status_code, 302)
        self.assertEqual(entered['Location'], '/oauth/mcp/device')
        to_identity = self.client.get('/oauth/mcp/device')
        self.assertEqual(to_identity.status_code, 302)
        self.assertTrue(to_identity['Location'].startswith('http://id.test/oauth/authorize?'))
        state = parse_qs(urlsplit(to_identity['Location']).query)['state'][0]
        with patch('apps.global_mcp.oauth_views.oidc.complete', side_effect=_complete), patch(
            'apps.global_mcp.oauth_views.fetch_me', return_value=_profile()
        ):
            back = self.client.get('/oauth/mcp/signin/complete', {'state': state, 'code': 'x'})
        self.assertEqual(back.status_code, 302)
        self.assertEqual(back['Location'], '/oauth/mcp/device')
        return self.client.get('/oauth/mcp/device')

    def test_metadata_advertises_device_grant(self):
        body = self.client.get('/.well-known/oauth-authorization-server').json()
        self.assertEqual(body['device_authorization_endpoint'], 'http://ai.test/oauth/mcp/device/code')
        self.assertIn(DEVICE_GRANT, body['grant_types_supported'])

    def test_device_code_response_shape(self):
        start = self._start()
        self.assertEqual(start['verification_uri'], 'http://ai.test/oauth/mcp/device')
        self.assertRegex(start['user_code'], r'^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$')
        self.assertEqual(start['verification_uri_complete'], f"http://ai.test/oauth/mcp/device?user_code={start['user_code']}")
        self.assertEqual(start['expires_in'], 600)
        self.assertEqual(start['interval'], 5)
        row = McpDeviceAuthorization.objects.get()
        self.assertNotIn(start['device_code'], row.device_code_hash)
        self.assertNotEqual(row.user_code_hash, normalize_user_code(start['user_code']))
        self.assertEqual(self.client.post('/oauth/mcp/device/code', {}).status_code, 400)
        self.assertEqual(self.client.post('/oauth/mcp/device/code', {'client_id': 'nope'}).status_code, 401)

    def test_full_device_login_pending_slow_down_approve_and_one_time(self):
        start = self._start()
        pending = self._poll(start['device_code'], reset=False)
        self.assertEqual(pending.json()['error'], 'authorization_pending')
        fast = self._poll(start['device_code'], reset=False)
        self.assertEqual(fast.json()['error'], 'slow_down')
        self.assertEqual(McpDeviceAuthorization.objects.get().poll_interval, 10)

        consent = self._sign_in_and_open_consent(start)
        self.assertEqual(consent.status_code, 200)
        self.assertContains(consent, 'Connect Hermes &lt;Agent&gt;')
        self.assertContains(consent, 'Only continue if you started this from Hermes &lt;Agent&gt;.')
        self.assertContains(consent, 'Shellui does not verify it.')
        self.assertContains(consent, 'Access requested')
        self.assertContains(consent, 'http://ai.test/mcp')
        self.assertNotContains(consent, 'Hermes <Agent>')

        row = McpDeviceAuthorization.objects.get()
        approved = self.client.post(
            '/oauth/mcp/device',
            {'device': str(row.id), 'decision': 'allow', 'agent_name': 'Hermes', 'access_mode': 'read_only'},
        )
        self.assertContains(approved, 'Approved')
        row.refresh_from_db()
        self.assertEqual(row.status, McpDeviceAuthorization.STATUS_APPROVED)
        self.assertEqual(row.agent.access_mode, 'read_only')
        self.assertEqual(row.agent.owner_sub, 'user-1')

        token = self._poll(start['device_code'])
        self.assertEqual(token.status_code, 200, token.content)
        self.assertEqual(token.json()['token_type'], 'Bearer')
        self.assertTrue(token.json()['refresh_token'])
        self.assertTrue(
            GlobalAgentTokenAudit.objects.filter(event_type=GlobalAgentTokenAudit.EVENT_DEVICE_EXCHANGE).exists()
        )
        mcp = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f"Bearer {token.json()['access_token']}",
        )
        self.assertEqual(mcp.status_code, 200, mcp.content)

        replay = self._poll(start['device_code'])
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()['error'], 'invalid_grant')
        reuse = self.client.get('/oauth/mcp/device', {'user_code': start['user_code']})
        self.assertEqual(reuse.status_code, 400)

    def test_deny(self):
        start = self._start()
        self._sign_in_and_open_consent(start)
        row = McpDeviceAuthorization.objects.get()
        self.client.post('/oauth/mcp/device', {'device': str(row.id), 'decision': 'deny'})
        self.assertEqual(self._poll(start['device_code']).json()['error'], 'access_denied')

    def test_expiry(self):
        start = self._start()
        McpDeviceAuthorization.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self._poll(start['device_code']).json()['error'], 'expired_token')
        page = self.client.get('/oauth/mcp/device', {'user_code': start['user_code']})
        self.assertEqual(page.status_code, 400)

    def test_approved_then_expired_revokes_agent(self):
        start = self._start()
        self._sign_in_and_open_consent(start)
        row = McpDeviceAuthorization.objects.get()
        self.client.post('/oauth/mcp/device', {'device': str(row.id), 'decision': 'allow'})
        McpDeviceAuthorization.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self._poll(start['device_code']).json()['error'], 'expired_token')
        row.refresh_from_db()
        self.assertIsNotNone(row.agent.revoked_at)

    def test_wrong_client_and_bad_codes(self):
        start = self._start()
        other = self.client.post(
            '/oauth/mcp/token',
            {'grant_type': DEVICE_GRANT, 'device_code': start['device_code'], 'client_id': 'other'},
        )
        self.assertEqual(other.status_code, 401)
        self.assertEqual(self._poll('not-a-code').json()['error'], 'invalid_grant')
        self.assertContains(self.client.get('/oauth/mcp/device'), 'Eight letters or digits')
        self.assertEqual(self.client.post('/oauth/mcp/device', {'user_code': 'AAAA-AAAA'}).status_code, 400)
        lower = start['user_code'].lower().replace('-', ' ')
        self.assertEqual(self.client.post('/oauth/mcp/device', {'user_code': lower}).status_code, 302)

    def test_code_entry_is_rate_limited(self):
        for _ in range(30):
            self.client.post('/oauth/mcp/device', {'user_code': 'AAAA-AAAA'})
        self.assertEqual(self.client.post('/oauth/mcp/device', {'user_code': 'AAAA-AAAA'}).status_code, 429)

    def test_decision_without_session_is_refused(self):
        start = self._start()
        row = McpDeviceAuthorization.objects.get()
        self.client.get('/oauth/mcp/device', {'user_code': start['user_code']})
        response = self.client.post('/oauth/mcp/device', {'device': str(row.id), 'decision': 'allow'})
        self.assertEqual(response.status_code, 400)
        row.refresh_from_db()
        self.assertEqual(row.status, McpDeviceAuthorization.STATUS_PENDING)


@override_settings(**GLOBAL)
class McpChallengeTests(TestCase):
    def test_get_without_token_is_401_with_scope(self):
        for method in ('get', 'post', 'delete'):
            with self.subTest(method=method):
                response = getattr(self.client, method)('/mcp')
                self.assertEqual(response.status_code, 401)
                header = response['WWW-Authenticate']
                self.assertIn('scope="mcp"', header)
                self.assertIn('resource_metadata="http://ai.test/.well-known/oauth-protected-resource"', header)
                self.assertNotIn('error=', header)

    def test_bad_token_keeps_invalid_token_error(self):
        response = self.client.get('/mcp', HTTP_AUTHORIZATION='Bearer nope')
        self.assertEqual(response.status_code, 401)
        self.assertIn('error="invalid_token"', response['WWW-Authenticate'])
        self.assertIn('scope="mcp"', response['WWW-Authenticate'])
