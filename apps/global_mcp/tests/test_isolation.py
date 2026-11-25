"""Cross-user and cross-company isolation for global MCP and the connections API.

Uses real RS256 token shapes: MCP access tokens, saas_api JWTs minted by
issue_saas_api_token, and identity-global access JWTs (iss/aud/sub/exp/kid).
The fake saas directory decodes the bearer and returns only that subject\'s projects,
matching companies_for(principal.sub) on saas-service.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from unittest.mock import patch

import jwt
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.authapi.ai_service_jwks import build_jwks_document
from apps.global_mcp.company_tools import company_rows, region_urls
from apps.global_mcp.grants import GlobalAgentCompanyGrant, maybe_setup_grant
from apps.global_mcp.models import GlobalAgent, McpOAuthClient
from apps.global_mcp.tests.test_global_mode import GLOBAL, _PRIVATE, _PUBLIC, _SIGNING
from apps.global_mcp.tokens import issue_mcp_access_token, issue_saas_api_token


def _company(name: str, *, region: str = 'ch') -> dict:
    """Shape of saas-service CompanySerializer (region is a code string)."""
    return {
        'id': str(uuid.uuid4()),
        'name': name,
        'region': region,
        'region_name': 'Switzerland' if region == 'ch' else 'European Union',
        'status': 'active',
        'plan': 'free',
        'access_mode': 'public',
        'allowed_email_domains': [],
        'limits': {},
        'limits_version': 1,
        'regional_company_id': '42' if name.startswith('Alpha') else '99',
        'admin_url': 'http://admin.region',
        'identity_url': 'http://id.region',
        'email_url': 'http://email.region',
        'storage_url': 'http://storage.region',
        'hosting_url': 'http://hosting.region',
        'files_url': 'http://files.region',
        'ai_url': 'http://ai.region',
        'failure_reason': '',
        'role': 'owner',
        'icon_url': '',
        'links': [],
    }


SETTINGS = {
    **GLOBAL,
    'GLOBAL_IDENTITY_JWKS_DOCUMENT': build_jwks_document(_SIGNING),
    'GLOBAL_IDENTITY_AUDIENCE': 'shellui',
}


def identity_access_token(*, sub: str, email: str, aud: str = 'shellui', extra: dict | None = None) -> str:
    now = timezone.now()
    claims = {
        'iss': 'http://id.test',
        'aud': aud,
        'sub': sub,
        'email': email,
        'exp': int((now + timedelta(minutes=5)).timestamp()),
        'iat': int(now.timestamp()),
    }
    if extra:
        claims.update(extra)
    return jwt.encode(
        claims,
        _PRIVATE,
        algorithm='RS256',
        headers={'kid': _SIGNING.kid},
    )


@override_settings(**SETTINGS)
class CompanyPayloadShapeTests(TestCase):
    def test_company_rows_accepts_array_and_wrappers(self):
        rows = [{'id': '1'}]
        self.assertEqual(company_rows(rows), rows)
        self.assertEqual(company_rows({'results': rows}), rows)
        self.assertEqual(company_rows({'companies': rows}), rows)
        self.assertEqual(company_rows({'results': 'nope'}), [])
        self.assertEqual(company_rows(None), [])

    def test_region_urls_reads_serializer_string_region(self):
        ai_url, identity_url, code = region_urls(
            {'region': 'eu', 'ai_url': 'https://ai.eu.example', 'identity_url': 'https://id.eu.example'}
        )
        self.assertEqual(code, 'eu')
        self.assertEqual(ai_url, 'https://ai.eu.example')
        self.assertEqual(identity_url, 'https://id.eu.example')
        _ai, _identity, wrapped = region_urls({'region': {'code': 'ch', 'ai_url': 'http://ai.ch'}})
        self.assertEqual(wrapped, 'ch')


@override_settings(**SETTINGS)
class CrossUserIsolationTests(TestCase):
    def setUp(self):
        self.company_a = _company('Alpha')
        self.company_b = _company('Bravo', region='eu')
        self.directory = {
            'user-a': [self.company_a],
            'user-b': [self.company_b],
        }
        client_a = McpOAuthClient.objects.create(client_id='client-a', client_name='Hermes A')
        client_b = McpOAuthClient.objects.create(client_id='client-b', client_name='Hermes B')
        self.agent_a = GlobalAgent.objects.create(
            name='Agent A',
            owner_sub='user-a',
            owner_email='a@example.com',
            oauth_client=client_a,
            access_mode=GlobalAgent.ACCESS_ASK,
            read_level=GlobalAgent.READ_SAFE,
            services_allowed=['saas'],
        )
        self.agent_b = GlobalAgent.objects.create(
            name='Agent B',
            owner_sub='user-b',
            owner_email='b@example.com',
            oauth_client=client_b,
            access_mode=GlobalAgent.ACCESS_ASK,
            read_level=GlobalAgent.READ_SAFE,
            services_allowed=['saas'],
        )
        maybe_setup_grant(self.agent_a, self.company_a)
        self.token_a, _ = issue_mcp_access_token(self.agent_a)
        self.token_b, _ = issue_mcp_access_token(self.agent_b)
        self.seen_subs: list[str] = []

    def _decode_saas(self, token: str) -> dict:
        claims = jwt.decode(
            token,
            _PUBLIC,
            algorithms=['RS256'],
            audience='http://saas.test/api',
            issuer='http://ai.test',
        )
        self.assertEqual(claims['token_type'], 'saas_api')
        self.assertEqual(claims['iss'], 'http://ai.test')
        self.assertTrue(claims.get('agent_id'))
        return claims

    def _saas(self, method, path, token=None, **_kwargs):
        claims = self._decode_saas(token)
        sub = claims['sub']
        self.seen_subs.append(sub)
        rows = self.directory.get(sub, [])
        if method.upper() == 'GET' and path == '/api/v1/companies':
            return 200, rows
        prefix = '/api/v1/companies/'
        if method.upper() == 'GET' and path.startswith(prefix):
            company_id = path[len(prefix) :].split('/', 1)[0]
            for row in rows:
                if row['id'] == company_id:
                    return 200, row
            return 404, {'detail': 'Company not found.'}
        return 404, {'detail': 'Not found.'}

    def _call(self, token, name, arguments=None):
        return self.client.post(
            '/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'tools/call',
                    'params': {'name': name, 'arguments': arguments or {}},
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )

    def _listed(self, token):
        response = self._call(token, 'ai_list_companies')
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()['result']
        self.assertFalse(body.get('isError'), body)
        payload = json.loads(body['content'][0]['text'])
        return payload['companies']

    def test_list_companies_returns_only_the_caller_projects(self):
        with patch('apps.global_mcp.company_tools.request_json', side_effect=self._saas):
            listed_a = self._listed(self.token_a)
            listed_b = self._listed(self.token_b)
        self.assertEqual([row['name'] for row in listed_a], ['Alpha'])
        self.assertEqual([row['region'] for row in listed_a], ['ch'])
        self.assertEqual(listed_a[0]['ai_url'], 'http://ai.region')
        self.assertIsNotNone(listed_a[0]['delegation'])
        self.assertEqual([row['name'] for row in listed_b], ['Bravo'])
        self.assertEqual([row['region'] for row in listed_b], ['eu'])
        self.assertIsNone(listed_b[0]['delegation'])
        self.assertEqual(self.seen_subs, ['user-a', 'user-b'])
        self.assertNotEqual(listed_a[0]['id'], listed_b[0]['id'])

    def test_list_companies_still_accepts_wrapped_dicts(self):
        def wrapped(method, path, token=None, **kwargs):
            status, payload = self._saas(method, path, token=token, **kwargs)
            if path == '/api/v1/companies' and isinstance(payload, list):
                return status, {'results': payload}
            return status, payload

        with patch('apps.global_mcp.company_tools.request_json', side_effect=wrapped):
            names = [row['name'] for row in self._listed(self.token_a)]
        self.assertEqual(names, ['Alpha'])

        def companies_key(method, path, token=None, **kwargs):
            status, payload = self._saas(method, path, token=token, **kwargs)
            if path == '/api/v1/companies' and isinstance(payload, list):
                return status, {'companies': payload}
            return status, payload

        with patch('apps.global_mcp.company_tools.request_json', side_effect=companies_key):
            names = [row['name'] for row in self._listed(self.token_b)]
        self.assertEqual(names, ['Bravo'])

    def test_caller_token_cannot_read_another_company(self):
        tools = (
            'ai_call_company_tool',
            'ai_company_search_tools',
            'ai_company_describe_tool',
            'ai_grant_company_access',
            'ai_revoke_company_access',
        )
        with patch('apps.global_mcp.company_tools.request_json', side_effect=self._saas):
            for name in tools:
                with self.subTest(name=name):
                    arguments = {'company_id': self.company_a['id']}
                    if name == 'ai_call_company_tool':
                        arguments['tool'] = 'identity_list_users'
                    if name == 'ai_company_search_tools':
                        arguments['query'] = 'users'
                    if name == 'ai_company_describe_tool':
                        arguments['names'] = ['identity_list_users']
                    response = self._call(self.token_b, name, arguments)
                    result = response.json()['result']
                    self.assertTrue(result.get('isError'), result)
                    text = result['content'][0]['text']
                    self.assertIn('Project was not found', text)
                    self.assertNotIn('Alpha', text)
                    self.assertNotIn(self.company_a['id'], text)

    def test_token_for_one_company_fails_on_another(self):
        with patch('apps.global_mcp.company_tools.request_json', side_effect=self._saas):
            response = self._call(
                self.token_a,
                'ai_call_company_tool',
                {'company_id': self.company_b['id'], 'tool': 'identity_list_users'},
            )
        result = response.json()['result']
        self.assertTrue(result.get('isError'), result)
        self.assertIn('Project was not found', result['content'][0]['text'])
        self.assertNotIn('Bravo', result['content'][0]['text'])

    def test_empty_search_hint_does_not_mention_missing_list_services(self):
        response = self._call(self.token_a, 'ai_search_tools', {'query': 'zzzz-no-such-tool'})
        result = response.json()['result']
        self.assertFalse(result.get('isError'), result)
        payload = json.loads(result['content'][0]['text'])
        self.assertEqual(payload['matches'], [])
        self.assertIn('ai_list_companies', payload['hint'])
        self.assertNotIn('ai_list_services', payload['hint'])

    def test_minted_saas_token_is_bound_to_the_agent_owner(self):
        token, claims = issue_saas_api_token(self.agent_b, purpose='check')
        self.assertEqual(claims['sub'], 'user-b')
        self.assertEqual(claims['agent_id'], str(self.agent_b.id))
        self.assertEqual(claims['token_type'], 'saas_api')
        decoded = jwt.decode(
            token,
            _PUBLIC,
            algorithms=['RS256'],
            audience='http://saas.test/api',
            issuer='http://ai.test',
        )
        self.assertEqual(decoded['sub'], 'user-b')
        self.assertNotEqual(decoded['sub'], 'user-a')


@override_settings(**SETTINGS)
class GlobalAgentConnectionIsolationTests(TestCase):
    def setUp(self):
        client = McpOAuthClient.objects.create(client_id='hermes', client_name='Hermes')
        self.agent_a = GlobalAgent.objects.create(
            name='Device A',
            owner_sub='user-a',
            owner_email='a@example.com',
            oauth_client=client,
            access_mode=GlobalAgent.ACCESS_ASK,
            read_level=GlobalAgent.READ_SAFE,
            services_allowed=['saas'],
        )
        self.agent_b = GlobalAgent.objects.create(
            name='Device B',
            owner_sub='user-b',
            owner_email='b@example.com',
            access_mode=GlobalAgent.ACCESS_ASK,
            read_level=GlobalAgent.READ_SAFE,
            services_allowed=['saas'],
        )
        self.session_a = identity_access_token(sub='user-a', email='a@example.com')
        self.session_b = identity_access_token(sub='user-b', email='b@example.com')

    def test_list_returns_only_the_caller_agents(self):
        listed_a = self.client.get('/ai/v1/mcp/global/agents', HTTP_AUTHORIZATION=f'Bearer {self.session_a}')
        listed_b = self.client.get('/ai/v1/mcp/global/agents', HTTP_AUTHORIZATION=f'Bearer {self.session_b}')
        self.assertEqual(listed_a.status_code, 200, listed_a.content)
        self.assertEqual(listed_b.status_code, 200, listed_b.content)
        ids_a = [row['id'] for row in listed_a.json()['agents']]
        ids_b = [row['id'] for row in listed_b.json()['agents']]
        self.assertEqual(ids_a, [str(self.agent_a.id)])
        self.assertEqual(ids_b, [str(self.agent_b.id)])
        self.assertEqual(listed_a.json()['agents'][0]['kind'], 'oauth')
        self.assertEqual(listed_a.json()['agents'][0]['oauth_client_id'], 'hermes')
        self.assertTrue(listed_a.json()['agents'][0]['is_active'])

    def test_caller_cannot_revoke_another_users_agent(self):
        response = self.client.post(
            f'/ai/v1/mcp/global/agents/{self.agent_a.id}/revoke',
            HTTP_AUTHORIZATION=f'Bearer {self.session_b}',
        )
        self.assertEqual(response.status_code, 404)
        self.agent_a.refresh_from_db()
        self.assertIsNone(self.agent_a.revoked_at)

    def test_owner_can_revoke_their_agent(self):
        response = self.client.post(
            f'/ai/v1/mcp/global/agents/{self.agent_a.id}/revoke',
            HTTP_AUTHORIZATION=f'Bearer {self.session_a}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()['agent']['revoked_at'])
        self.assertFalse(response.json()['agent']['is_active'])
        self.agent_a.refresh_from_db()
        self.assertIsNotNone(self.agent_a.revoked_at)

    def test_mcp_and_saas_tokens_are_rejected_on_the_connections_api(self):
        mcp, _ = issue_mcp_access_token(self.agent_a)
        saas, _ = issue_saas_api_token(self.agent_a)
        for token in (mcp, saas, 'not-a-jwt', identity_access_token(sub='user-a', email='a@example.com', aud='other')):
            with self.subTest(token=token[:12]):
                response = self.client.get('/ai/v1/mcp/global/agents', HTTP_AUTHORIZATION=f'Bearer {token}')
                self.assertEqual(response.status_code, 401)

    def test_unauthenticated_list_is_401(self):
        response = self.client.get('/ai/v1/mcp/global/agents')
        self.assertEqual(response.status_code, 401)


@override_settings(**SETTINGS)
class AutoCompanyAccessTests(TestCase):
    """Projects the owner belongs to are granted on first use, checked on saas every call."""

    def setUp(self):
        from django.core.cache import cache

        cache.clear()
        self.alpha = _company('Alpha')
        self.bravo = _company('Bravo', region='eu')
        self.alpha['role'] = 'staff'
        self.directory = {'user-a': [self.alpha], 'user-b': [self.bravo]}
        client = McpOAuthClient.objects.create(client_id='hermes', client_name='Hermes')
        self.agent_a = GlobalAgent.objects.create(
            name='Agent A',
            owner_sub='user-a',
            owner_email='a@example.com',
            oauth_client=client,
            access_mode=GlobalAgent.ACCESS_FULL,
            allow_destructive_without_asking=True,
            read_level=GlobalAgent.READ_SAFE,
            services_allowed=['saas'],
        )
        self.token_a, _ = issue_mcp_access_token(self.agent_a)
        self.exchanges: list[dict] = []
        self.regional_calls: list[tuple[str, str]] = []
        self.regional_body = {'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': False}}

    def _saas(self, method, path, token=None, **_kwargs):
        sub = CrossUserIsolationTests._decode_saas(self, token)['sub']
        rows = self.directory.get(sub, [])
        prefix = '/api/v1/companies/'
        if method.upper() == 'GET' and path.startswith(prefix):
            company_id = path[len(prefix) :].split('/', 1)[0]
            for row in rows:
                if row['id'] == company_id:
                    return 200, row
        return 404, {'detail': 'Company not found.'}

    def _post(self, url, json=None, headers=None, timeout=None):
        test = self

        class Response:
            status_code = 200
            headers = {'Content-Type': 'application/json'}
            text = ''

            def json(self):
                if str(url).endswith('/oauth/mcp/token'):
                    test.exchanges.append(json_body)
                    return {'access_token': f"regional-{json_body['company_id']}", 'expires_in': 300}
                test.regional_calls.append((str(url), headers['Authorization']))
                return test.regional_body

        json_body = json
        return Response()

    def _call(self, name, arguments):
        with patch('apps.global_mcp.company_tools.request_json', side_effect=self._saas), patch(
            'apps.global_mcp.company_tools.requests.post', side_effect=self._post
        ), patch('apps.global_mcp.grants.request_json', return_value=(202, {})):
            response = CrossUserIsolationTests._call(self, self.token_a, name, arguments)
        return response.json()['result']

    def _subject(self, index=-1) -> dict:
        return jwt.decode(
            self.exchanges[index]['subject_token'],
            _PUBLIC,
            algorithms=['RS256'],
            audience='shellui-agents',
            issuer='http://ai.test',
        )

    def test_member_gets_read_write_on_first_use_without_approval(self):
        result = self._call('ai_company_search_tools', {'company_id': self.alpha['id'], 'query': 'list users'})
        self.assertFalse(result.get('isError'), result)
        self.assertNotIn('approval_url', result['content'][0]['text'])
        grant = GlobalAgentCompanyGrant.objects.get(agent=self.agent_a, global_company_id=self.alpha['id'])
        self.assertEqual(grant.max_access_mode, GlobalAgent.ACCESS_ASK)
        self.assertFalse(grant.max_destructive)
        subject = self._subject()
        self.assertEqual(subject['sub'], 'user-a')
        self.assertEqual(subject['mcp_access'], 'ask')
        self.assertIs(subject['mcp_destructive'], False)
        self.assertEqual(self.exchanges[-1]['company_id'], 42)

    def test_non_member_cannot_auto_grant_another_users_project(self):
        for name in ('ai_company_search_tools', 'ai_call_company_tool', 'ai_company_describe_tool'):
            with self.subTest(name=name):
                arguments = {
                    'company_id': self.bravo['id'],
                    'query': 'users',
                    'tool': 'identity_list_users',
                    'names': ['identity_list_users'],
                    'role': 'owner',
                    'owner_sub': 'user-b',
                }
                result = self._call(name, {k: v for k, v in arguments.items() if k != 'query' or name.endswith('search_tools')})
                self.assertTrue(result.get('isError'), result)
                self.assertIn('Project was not found', result['content'][0]['text'])
        self.assertFalse(GlobalAgentCompanyGrant.objects.filter(global_company_id=self.bravo['id']).exists())
        self.assertEqual(self.exchanges, [])
        self.assertEqual(self.regional_calls, [])

    def test_member_without_a_role_is_refused(self):
        self.alpha['role'] = ''
        result = self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        self.assertTrue(result.get('isError'), result)
        self.assertIn('not a member', result['content'][0]['text'])
        self.assertFalse(GlobalAgentCompanyGrant.objects.exists())

    def test_removed_member_loses_access(self):
        self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        self.assertEqual(len(self.regional_calls), 1)
        self.directory['user-a'] = []
        result = self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        self.assertTrue(result.get('isError'), result)
        self.assertIn('Project was not found', result['content'][0]['text'])
        self.assertEqual(len(self.regional_calls), 1)

    def test_revoked_connection_loses_access_and_revokes_grants(self):
        self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        session = identity_access_token(sub='user-a', email='a@example.com')
        with patch('apps.global_mcp.grants.request_json', return_value=(202, {})) as fanout:
            revoked = self.client.post(
                f'/ai/v1/mcp/global/agents/{self.agent_a.id}/revoke', HTTP_AUTHORIZATION=f'Bearer {session}'
            )
        self.assertEqual(revoked.status_code, 200, revoked.content)
        self.assertEqual(fanout.call_args.args[1], '/api/v1/internal/ai-global/revoke')
        self.assertFalse(GlobalAgentCompanyGrant.objects.filter(revoked_at__isnull=True).exists())
        with patch('apps.global_mcp.company_tools.requests.post', side_effect=self._post):
            response = CrossUserIsolationTests._call(
                self, self.token_a, 'ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'}
            )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(len(self.regional_calls), 1)

    def test_revoked_project_grant_is_not_restored_automatically(self):
        self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        self.assertFalse(self._call('ai_revoke_company_access', {'company_id': self.alpha['id']}).get('isError'))
        result = self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        self.assertTrue(result.get('isError'), result)
        self.assertIn('revoked', result['content'][0]['text'])
        self.assertEqual(len(self.regional_calls), 1)

    def test_destructive_tools_still_ask(self):
        self.regional_body = {
            'result': {
                'content': [{'type': 'text', 'text': 'Approval required.'}],
                'approval_url': 'http://id.region/oauth/mcp/approval/x',
                'isError': False,
            }
        }
        result = self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_delete_users'})
        body = json.loads(result['content'][0]['text'])
        self.assertEqual(body['result']['approval_url'], 'http://id.region/oauth/mcp/approval/x')
        self.assertIs(self._subject()['mcp_destructive'], False)

    def test_regional_token_for_one_company_is_not_used_for_another(self):
        second = _company('Alpha Two')
        second['regional_company_id'] = '43'
        self.directory['user-a'].append(second)
        self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        self._call('ai_call_company_tool', {'company_id': second['id'], 'tool': 'identity_list_users'})
        self.assertEqual([row['company_id'] for row in self.exchanges], [42, 43])
        self.assertEqual(self._subject(0)['global_company_id'], self.alpha['id'])
        self.assertEqual(self._subject(1)['global_company_id'], second['id'])
        self.assertEqual(
            self.regional_calls,
            [('http://ai.region/c/42/mcp', 'Bearer regional-42'), ('http://ai.region/c/43/mcp', 'Bearer regional-43')],
        )

    def test_explicit_read_only_grant_is_kept_and_members_can_narrow(self):
        self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        narrowed = self._call('ai_grant_company_access', {'company_id': self.alpha['id'], 'access_mode': 'read_only'})
        self.assertIn('narrowed', narrowed['content'][0]['text'])
        self._call('ai_call_company_tool', {'company_id': self.alpha['id'], 'tool': 'identity_list_users'})
        self.assertEqual(self._subject()['mcp_access'], 'read_only')
        widened = self._call('ai_grant_company_access', {'company_id': self.alpha['id'], 'access_mode': 'full'})
        self.assertTrue(widened.get('isError'), widened)
        self.assertIn('Only an owner', widened['content'][0]['text'])

    def test_global_search_points_to_project_tools(self):
        result = self._call('ai_search_tools', {'query': 'list users'})
        payload = json.loads(result['content'][0]['text'])
        self.assertIn('ai_company_search_tools', payload['project_tools'])
