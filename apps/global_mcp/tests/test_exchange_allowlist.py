"""Regional token exchange stays on the configured host allowlist."""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import urlsplit

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from apps.global_mcp.company_tools import call_regional, forward_company_tool
from apps.global_mcp.exchange import ExchangeError, regional_access_token
from apps.global_mcp.exchange_allowlist import exchange_url_allowed
from apps.global_mcp.grants import maybe_setup_grant
from apps.global_mcp.models import GlobalAgent

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))

GLOBAL = dict(
    AI_SERVICE_MODE='global',
    AI_SERVICE_ISSUER='https://ai.test',
    AI_PUBLIC_URL='https://ai.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_SIGNING_KID=_SIGNING.kid,
    GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE='shellui-agents',
    DEBUG=False,
)


def _company(**urls) -> dict:
    company_id = str(uuid.uuid4())
    return {
        'id': company_id,
        'role': 'owner',
        'regional_company_id': '42',
        'status': 'active',
        'region': {'code': 'ch', **urls},
    }


@override_settings(**GLOBAL)
class ExchangeAllowlistTests(TestCase):
    def setUp(self):
        self.agent = GlobalAgent.objects.create(
            name='Inspector',
            owner_sub='user-1',
            owner_email='owner@example.com',
            access_mode=GlobalAgent.ACCESS_ASK,
            read_level=GlobalAgent.READ_SAFE,
            services_allowed=['ai', 'identity'],
            setup_flow=True,
            setup_expires_at=timezone.now() + timedelta(minutes=12),
        )

    def _exchange(self, *, identity_url: str, resource: str, company: dict | None = None):
        row = company or _company(ai_url='https://ai.ch.shellui.com', identity_url=identity_url)
        return regional_access_token(
            self.agent,
            row,
            identity_url=identity_url,
            resource=resource,
            services=['ai'],
            binding_version=1,
            access_mode='ask',
            read_level='safe',
            destructive=False,
        )

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=['.shellui.com'])
    def test_unlisted_host_does_not_receive_the_subject_token(self):
        with patch('apps.global_mcp.exchange.requests.post') as post:
            with self.assertRaises(ExchangeError) as caught:
                self._exchange(
                    identity_url='https://evil.example',
                    resource='https://evil.example/c/42/mcp',
                )
        post.assert_not_called()
        self.assertNotIn('evil.example', str(caught.exception))

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=['.shellui.com'])
    def test_lookalike_suffix_is_refused(self):
        with patch('apps.global_mcp.exchange.requests.post') as post:
            with self.assertRaises(ExchangeError):
                self._exchange(
                    identity_url='https://shellui.com.evil.example',
                    resource='https://ai.shellui.com.evil.example/c/42/mcp',
                )
        post.assert_not_called()

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=['id.shellui.com', 'ai.shellui.com'])
    def test_http_is_refused_when_debug_is_false(self):
        with patch('apps.global_mcp.exchange.requests.post') as post:
            with self.assertRaises(ExchangeError):
                self._exchange(
                    identity_url='http://id.shellui.com',
                    resource='http://ai.shellui.com/c/42/mcp',
                )
        post.assert_not_called()

    @override_settings(DEBUG=True, REGIONAL_EXCHANGE_ALLOWED_HOSTS=['id.region', 'ai.region'])
    def test_http_is_allowed_when_debug_is_true(self):
        with patch('apps.global_mcp.exchange.requests.post') as post:
            post.return_value.status_code = 200
            post.return_value.json.return_value = {'access_token': 'regional', 'expires_in': 60}
            token = self._exchange(
                identity_url='http://id.region',
                resource='http://ai.region/c/42/mcp',
            )
        self.assertEqual(token, 'regional')
        self.assertEqual(urlsplit(post.call_args.args[0]).hostname, 'id.region')
        self.assertEqual(post.call_args.args[0], 'http://id.region/oauth/mcp/token')

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=['.shellui.com'])
    def test_suffix_allows_https_and_does_not_follow_redirects(self):
        with patch('apps.global_mcp.exchange.requests.post') as post:
            post.return_value.status_code = 200
            post.return_value.json.return_value = {'access_token': 'regional', 'expires_in': 60}
            token = self._exchange(
                identity_url='https://id.ch.shellui.com',
                resource='https://ai.ch.shellui.com/c/42/mcp',
            )
        self.assertEqual(token, 'regional')
        self.assertEqual(urlsplit(post.call_args.args[0]).scheme, 'https')
        self.assertEqual(urlsplit(post.call_args.args[0]).hostname, 'id.ch.shellui.com')
        self.assertIs(post.call_args.kwargs.get('allow_redirects'), False)

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=['.shellui.com'])
    def test_company_record_outside_the_list_is_not_called(self):
        company = _company(ai_url='https://evil.example', identity_url='https://evil.example')
        maybe_setup_grant(self.agent, company)
        with patch('apps.global_mcp.exchange.requests.post') as post:
            result = forward_company_tool(
                self.agent,
                company,
                'identity_list_users',
                {},
                correlation_id='corr',
            )
        self.assertEqual(result['error'], 'Region URL is not an allowed exchange host.')
        post.assert_not_called()

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=['ai.shellui.com'])
    def test_call_regional_refuses_an_unlisted_host(self):
        with patch('apps.global_mcp.company_tools.requests.post') as post:
            result = call_regional(
                'https://evil.example/c/42/mcp',
                'regional-token',
                'identity_list_users',
                {},
                correlation_id='corr',
            )
        self.assertEqual(result['error'], 'Region URL is not an allowed exchange host.')
        post.assert_not_called()

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=[])
    def test_empty_allowlist_refuses_every_host(self):
        self.assertFalse(exchange_url_allowed('https://id.shellui.com'))
        self.assertFalse(exchange_url_allowed('https://id.shellui.com.evil.example'))

    @override_settings(REGIONAL_EXCHANGE_ALLOWED_HOSTS=['id.shellui.com:8443'])
    def test_exact_host_matches_only_the_listed_port(self):
        self.assertTrue(exchange_url_allowed('https://id.shellui.com:8443/oauth/mcp/token'))
        self.assertFalse(exchange_url_allowed('https://id.shellui.com/oauth/mcp/token'))
        self.assertFalse(exchange_url_allowed('https://ai.id.shellui.com/oauth/mcp/token'))
        self.assertFalse(exchange_url_allowed('https://user:secret@id.shellui.com:8443/oauth/mcp/token'))
        self.assertFalse(exchange_url_allowed('https://id.shellui.com:8443/oauth/mcp/token?next=https://evil.example'))
