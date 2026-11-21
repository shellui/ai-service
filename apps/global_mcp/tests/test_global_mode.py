"""Global MCP authorization server, saas tools, company tools, and grants."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import jwt
from django.core.checks import run_checks
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair, load_ai_service_signing_key
from apps.connector.mcp_call_store import correlation_from_request, persist_mcp_call
from apps.connector.models import McpCallLog
from apps.global_mcp.company_tools import parse_sse_relay
from apps.global_mcp.grants import GlobalAgentCompanyGrant, maybe_setup_grant, narrow_grant, normalize_grant_request
from apps.global_mcp.models import GlobalAgent, McpOAuthClient
from apps.global_mcp.openapi_tools import store_schema
from apps.global_mcp.pkce import new_verifier, s256_challenge
from apps.global_mcp.saas_client import MeProfile
from apps.global_mcp.tokens import issue_subject_token

_PRIVATE, _PUBLIC = generate_rsa_key_pair(key_size=2048)
_SIGNING = load_ai_service_signing_key(private_pem=_PRIVATE, kid=compute_rsa_kid(_PUBLIC))

GLOBAL = dict(
    AI_SERVICE_MODE='global',
    ROOT_URLCONF='config.urls_global',
    AI_SERVICE_ISSUER='http://ai.test',
    AI_PUBLIC_URL='http://ai.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_SIGNING_KID=_SIGNING.kid,
    GLOBAL_IDENTITY_URL='http://id.test',
    GLOBAL_IDENTITY_INTERNAL_URL='http://id.test',
    GLOBAL_IDENTITY_ISSUER='http://id.test',
    GLOBAL_OIDC_CLIENT_ID='ai-global',
    GLOBAL_OIDC_CLIENT_SECRET='secret',
    GLOBAL_OIDC_REDIRECT_URI='http://ai.test/oauth/mcp/signin/complete',
    GLOBAL_AGENT_ACCESS_TOKEN_AUDIENCE='shellui-agents',
    SAAS_SERVICE_URL='http://saas.test',
    SAAS_SERVICE_INTERNAL_URL='http://saas.test',
    SAAS_API_AUDIENCE='http://saas.test/api',
    REGIONAL_EXCHANGE_ALLOWED_HOSTS=['ai.region', 'id.region'],
    GLOBAL_MCP_ACCESS_TOKEN_TTL_SECONDS=3600,
    GLOBAL_MCP_REFRESH_TOKEN_TTL_SECONDS=2592000,
    MCP_TOOLS_LIST_MODE='discovery',
    REGION_IDENTITY_CONFIGURED=False,
    GLOBAL_CONTROL_CONFIGURED=False,
    DEBUG=False,
)

SCHEMA = {
    'paths': {
        '/api/v1/me': {
            'get': {
                'operationId': 'api_v1_me_retrieve',
                'summary': 'Returns the signed-in Shellui account.',
                'x-mcp': {'read_only': True, 'destructive': False, 'name': 'saas_get_me'},
            }
        },
        '/api/v1/regions': {
            'get': {
                'operationId': 'api_v1_regions_list',
                'summary': 'Returns enabled Shellui regions.',
                'x-mcp': {'read_only': True, 'destructive': False, 'name': 'saas_list_regions'},
            }
        },
        '/api/v1/companies': {
            'post': {
                'operationId': 'api_v1_companies_create',
                'summary': 'Creates a Shellui project.',
                'x-mcp': {'read_only': False, 'destructive': False, 'name': 'saas_create_companies'},
                'requestBody': {
                    'content': {
                        'application/json': {
                            'schema': {
                                'type': 'object',
                                'required': ['name', 'region'],
                                'properties': {
                                    'name': {'type': 'string'},
                                    'region': {'type': 'string'},
                                },
                            }
                        }
                    }
                },
            }
        },
        '/api/v1/companies/{company_id}': {
            'delete': {
                'operationId': 'api_v1_companies_destroy',
                'summary': 'Deletes a project.',
                'x-mcp': {
                    'read_only': False,
                    'destructive': True,
                    'name': 'saas_delete_companies',
                    'global_description': 'Refuses to delete a Shellui project.',
                },
                'parameters': [
                    {'name': 'company_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
                ],
            }
        },
    }
}


def _profile():
    return MeProfile(
        sub='user-1',
        email='owner@example.com',
        name='Owner',
        raw={'sub': 'user-1', 'email': 'owner@example.com', 'terms_accepted': True, 'is_staff': False},
    )


@override_settings(**GLOBAL)
class GlobalOAuthTests(TestCase):
    def test_metadata_registration_pkce_and_refresh_rotation(self):
        metadata = self.client.get('/.well-known/oauth-authorization-server')
        self.assertEqual(metadata.status_code, 200)
        body = metadata.json()
        self.assertEqual(body['issuer'], 'http://ai.test')
        self.assertIn('refresh_token', body['grant_types_supported'])
        self.assertEqual(body['code_challenge_methods_supported'], ['S256'])
        protected = self.client.get('/.well-known/oauth-protected-resource')
        self.assertEqual(protected.json()['resource'], 'http://ai.test/mcp')
        registered = self.client.post(
            '/oauth/mcp/register',
            data=json.dumps(
                {'client_name': 'Inspector', 'redirect_uris': ['http://127.0.0.1:9/callback']}
            ),
            content_type='application/json',
        )
        self.assertEqual(registered.status_code, 201, registered.content)
        client_id = registered.json()['client_id']
        verifier = new_verifier()
        authorize = self.client.get(
            '/oauth/mcp/authorize',
            {
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': 'http://127.0.0.1:9/callback',
                'code_challenge': s256_challenge(verifier),
                'code_challenge_method': 'S256',
                'state': 'xyz',
                'resource': 'http://ai.test/mcp',
            },
        )
        self.assertEqual(authorize.status_code, 302)
        self.assertIn('/oauth/authorize', authorize['Location'])
        query = parse_qs(urlsplit(authorize['Location']).query)
        self.assertNotIn('prompt', query)
        self.assertEqual(query['code_challenge_method'], ['S256'])

        def complete(state, code):
            from apps.global_mcp.models import OidcTransaction

            row = OidcTransaction.objects.get(state=state)
            row.consumed_at = timezone.now()
            row.save(update_fields=['consumed_at'])
            return row, {'sub': 'user-1', 'email': 'owner@example.com', 'email_verified': True}

        with patch('apps.global_mcp.oauth_views.oidc.complete', side_effect=complete):
            done = self.client.get('/oauth/mcp/signin/complete', {'state': query['state'][0], 'code': 'oidc-code'})
        self.assertEqual(done.status_code, 302, done.content)
        consent = self.client.get(done['Location'])
        self.assertContains(consent, 'Shellui accounts')
        allowed = self.client.post(
            '/oauth/mcp/consent',
            {'request': consent.context['request_id'] if hasattr(consent, 'context') else '', 'decision': 'allow', 'agent_name': 'Inspector'},
        )
        # The consent page embeds the request id. Read it from the HTML when the template context is not exposed.
        if allowed.status_code != 302:
            request_id = consent.content.decode().split('name="request" value="')[1].split('"')[0]
            allowed = self.client.post(
                '/oauth/mcp/consent',
                {'request': request_id, 'decision': 'allow', 'agent_name': 'Inspector', 'access_mode': 'ask'},
            )
        self.assertEqual(allowed.status_code, 302, allowed.content)
        code = parse_qs(urlsplit(allowed['Location']).query)['code'][0]
        token = self.client.post(
            '/oauth/mcp/token',
            {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': 'http://127.0.0.1:9/callback',
                'client_id': client_id,
                'code_verifier': verifier,
            },
        )
        self.assertEqual(token.status_code, 200, token.content)
        self.assertIn('refresh_token', token.json())
        replay = self.client.post(
            '/oauth/mcp/token',
            {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': 'http://127.0.0.1:9/callback',
                'client_id': client_id,
                'code_verifier': verifier,
            },
        )
        self.assertEqual(replay.status_code, 400)
        refreshed = self.client.post(
            '/oauth/mcp/token',
            {'grant_type': 'refresh_token', 'refresh_token': token.json()['refresh_token']},
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.content)
        reused = self.client.post(
            '/oauth/mcp/token',
            {'grant_type': 'refresh_token', 'refresh_token': token.json()['refresh_token']},
        )
        self.assertEqual(reused.status_code, 400)
        family_dead = self.client.post(
            '/oauth/mcp/token',
            {'grant_type': 'refresh_token', 'refresh_token': refreshed.json()['refresh_token']},
        )
        self.assertEqual(family_dead.status_code, 400)

    def test_staff_terms_and_region_only_refusals(self):
        client = McpOAuthClient.objects.create(client_id='c', client_name='C', redirect_uris=['http://127.0.0.1:9/callback'])
        verifier = new_verifier()
        self.client.get(
            '/oauth/mcp/authorize',
            {
                'response_type': 'code',
                'client_id': client.client_id,
                'redirect_uri': 'http://127.0.0.1:9/callback',
                'code_challenge': s256_challenge(verifier),
                'code_challenge_method': 'S256',
            },
        )
        from apps.global_mcp.models import OidcTransaction

        state = OidcTransaction.objects.latest('created_at').state

        def complete(state_value, code):
            row = OidcTransaction.objects.get(state=state_value)
            return row, {'sub': 'user-1', 'email': 'owner@example.com', 'is_staff': True}

        with patch('apps.global_mcp.oauth_views.oidc.complete', side_effect=complete):
            page = self.client.get('/oauth/mcp/signin/complete', {'state': state, 'code': 'x'})
        self.assertContains(page, 'Staff accounts cannot authorize', status_code=403)

    def test_regional_token_on_global_mcp(self):
        regional = jwt.encode(
            {
                'iss': 'http://id.region',
                'aud': 'http://ai.region/c/10/mcp',
                'sub': 'agent:1',
                'company_id': 10,
                'exp': 9999999999,
                'iat': 1,
            },
            'secret',
            algorithm='HS256',
        )
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {regional}',
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'invalid_token')
        self.assertIn('Shellui accounts', response.json()['error_description'])
        self.assertIn('resource_metadata=', response['WWW-Authenticate'])
        self.assertEqual(self.client.get('/c/10/mcp').status_code, 404)


@override_settings(**GLOBAL)
class GlobalToolTests(TestCase):
    def setUp(self):
        store_schema(SCHEMA)
        self.agent = GlobalAgent.objects.create(
            name='Inspector',
            owner_sub='user-1',
            owner_email='owner@example.com',
            access_mode=GlobalAgent.ACCESS_ASK,
            read_level=GlobalAgent.READ_SAFE,
            services_allowed=['saas'],
            setup_flow=True,
            setup_expires_at=timezone.now() + timedelta(minutes=12),
        )
        from apps.global_mcp.tokens import issue_mcp_access_token

        self.token, _claims = issue_mcp_access_token(self.agent)

    def _call(self, name, arguments=None, token=None):
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
            HTTP_AUTHORIZATION=f'Bearer {token or self.token}',
        )

    def test_tools_list_is_discovery_and_destroy_is_refused(self):
        listed = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )
        names = {tool['name'] for tool in listed.json()['result']['tools']}
        self.assertIn('ai_search_tools', names)
        self.assertIn('ai_list_companies', names)
        self.assertIn('ai_grant_company_access', names)
        self.assertNotIn('saas_get_me', names)
        self.assertNotIn('ai_get_approval', names)
        from apps.global_mcp.mcp_views import _account_tool_names

        self.assertEqual(names, _account_tool_names())
        destroyed = self._call('saas_delete_companies', {'company_id': str(uuid.uuid4())})
        self.assertIn('does not delete', destroyed.json()['result']['content'][0]['text'])
        self.assertTrue(destroyed.json()['result']['isError'])

    def test_tools_list_omits_ai_get_approval_and_the_call_fails(self):
        listed = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )
        names = {tool['name'] for tool in listed.json()['result']['tools']}
        self.assertNotIn('ai_get_approval', names)
        full = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {'mode': 'all'}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )
        full_names = {tool['name'] for tool in full.json()['result']['tools']}
        self.assertNotIn('ai_get_approval', full_names)
        self.assertTrue(names <= full_names)
        response = self._call('ai_get_approval', {'approval_id': 'missing'})
        text = response.json()['result']['content'][0]['text']
        self.assertTrue(response.json()['result']['isError'])
        self.assertIn('not found', text.lower())
        wrapped = self._call('ai_call_tool', {'name': 'ai_get_approval', 'arguments': {'approval_id': 'missing'}})
        self.assertTrue(wrapped.json()['result']['isError'])
        self.assertIn('not found', wrapped.json()['result']['content'][0]['text'].lower())

    def test_create_company_asks_then_runs_and_writes_a_global_log(self):
        first = self._call('saas_create_companies', {'name': 'North', 'region': 'ch'})
        text = first.json()['result']['content'][0]['text']
        payload = json.loads(text)
        self.assertTrue(payload['approval_required'])
        from apps.global_mcp.models import GlobalMcpApprovalRequest

        approval = GlobalMcpApprovalRequest.objects.get(pk=payload['approval_id'])
        approval.status = GlobalMcpApprovalRequest.STATUS_APPROVED
        approval.save(update_fields=['status'])
        company_id = str(uuid.uuid4())
        created = {
            'id': company_id,
            'name': 'North',
            'status': 'provisioning',
            'role': 'owner',
            'regional_company_id': '42',
            'limits_version': 3,
            'region': {'code': 'ch', 'ai_url': 'https://ai.region', 'identity_url': 'https://id.region'},
        }
        with patch('apps.global_mcp.mcp_views.call_saas_tool', return_value=(201, created)):
            second = self._call('saas_create_companies', {'name': 'North', 'region': 'ch'})
        self.assertFalse(second.json()['result']['isError'])
        self.assertTrue(GlobalAgentCompanyGrant.objects.filter(agent=self.agent, global_company_id=company_id).exists())
        log = McpCallLog.objects.filter(plane='global', tool_name='saas_create_companies', status='allowed').first()
        self.assertIsNotNone(log)
        self.assertIsNone(log.company_id)
        self.assertEqual(log.owner_sub, 'user-1')
        self.assertIsNotNone(log.correlation_id)

    def test_company_call_relays_a_link_and_keeps_a_form(self):
        company_id = uuid.uuid4()
        company = {
            'id': str(company_id),
            'role': 'owner',
            'regional_company_id': '42',
            'limits_version': 1,
            'status': 'active',
            'region': {'code': 'ch', 'ai_url': 'https://ai.region', 'identity_url': 'https://id.region'},
        }
        maybe_setup_grant(self.agent, company)
        self.agent.setup_company_id = company_id
        self.agent.save(update_fields=['setup_company_id'])

        def fake_post(url, json=None, headers=None, timeout=None, **_kwargs):
            class Response:
                status_code = 200
                headers = {'Content-Type': 'application/json'}
                text = ''

                def json(self):
                    if str(url).endswith('/oauth/mcp/token'):
                        return {'access_token': 'regional-access', 'expires_in': 300, 'token_type': 'Bearer'}
                    return {
                        'result': {
                            'content': [{'type': 'text', 'text': 'ok'}],
                            'approval_url': 'http://id.region/oauth/mcp/approval/abc',
                            'isError': False,
                        }
                    }

            if not str(url).endswith('/oauth/mcp/token'):
                self.assertTrue(headers['X-Shellui-Correlation-Id'])
                self.assertEqual(json['params']['name'], 'identity_list_users')
            return Response()

        with patch('apps.global_mcp.company_tools.fetch_company', return_value=company), patch(
            'apps.global_mcp.company_tools.requests.post', side_effect=fake_post
        ):
            called = self._call(
                'ai_call_company_tool',
                {'company_id': str(company_id), 'tool': 'identity_list_users', 'arguments': {}},
            )
        self.assertFalse(called.json()['result'].get('isError'), called.content)
        body = json.loads(called.json()['result']['content'][0]['text'])
        self.assertEqual(body['result']['approval_url'], 'http://id.region/oauth/mcp/approval/abc')
        relay = parse_sse_relay(
            'event: message\ndata: {"jsonrpc":"2.0","id":"e1","method":"elicitation/create","params":{"mode":"form","message":"Allow?","requestedSchema":{"type":"object"}}}\n\n'
            'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}]}}\n\n'
        )
        self.assertEqual(relay['elicitation']['mode'], 'form')
        link = parse_sse_relay(
            'event: message\ndata: {"jsonrpc":"2.0","method":"elicitation/create","params":{"mode":"url","url":"http://id.region/approve","message":"Open"}}\n\n'
        )
        self.assertEqual(link['approval_url'], 'http://id.region/approve')
        self.assertEqual(link['elicitation']['mode'], 'url')

    def test_company_approval_copy_does_not_tell_the_agent_to_call_ai_get_approval(self):
        from apps.connector import mcp_approval_copy as regional
        from apps.global_mcp.copy import rewrite_relayed_approval_copy

        instruction = regional.pending_agent_instruction(tool_name='identity_create_invitations')
        self.assertIn('Call ai_get_approval', instruction)
        rewritten = rewrite_relayed_approval_copy(
            {
                'approval_url': 'http://id.region/oauth/mcp/approval/abc',
                'instruction': instruction,
                'message': regional.url_elicitation_message(tool_name='identity_create_invitations'),
                'name': 'ai_get_approval',
                '_relay_call': {'token': 'ai_get_approval'},
            }
        )
        self.assertEqual(rewritten['name'], 'ai_get_approval')
        self.assertEqual(rewritten['_relay_call']['token'], 'ai_get_approval')
        self.assertNotIn('Call ai_get_approval', rewritten['instruction'])
        self.assertNotIn('call ai_get_approval', rewritten['message'])
        self.assertIn('ai_call_company_tool', rewritten['instruction'])
        self.assertIn('same company_id, tool, and arguments', rewritten['instruction'])
        self.assertIn('ai_call_company_tool', rewritten['message'])

        company_id = uuid.uuid4()
        company = {
            'id': str(company_id),
            'role': 'owner',
            'regional_company_id': '42',
            'limits_version': 1,
            'status': 'active',
            'region': {'code': 'ch', 'ai_url': 'http://ai.region', 'identity_url': 'http://id.region'},
        }
        maybe_setup_grant(self.agent, company)

        def fake_post(url, json=None, headers=None, timeout=None):
            class Response:
                status_code = 200
                headers = {'Content-Type': 'application/json'}
                text = ''

                def json(self):
                    if str(url).endswith('/oauth/mcp/token'):
                        return {'access_token': 'regional-access', 'expires_in': 300, 'token_type': 'Bearer'}
                    return {
                        'result': {
                            'content': [
                                {
                                    'type': 'text',
                                    'text': regional.pending_agent_instruction(
                                        tool_name='identity_create_invitations'
                                    ),
                                }
                            ],
                            'instruction': regional.pending_agent_instruction(
                                tool_name='identity_create_invitations'
                            ),
                            'approval_url': 'http://id.region/oauth/mcp/approval/abc',
                            'isError': False,
                        }
                    }

            return Response()

        with patch('apps.global_mcp.company_tools.fetch_company', return_value=company), patch(
            'apps.global_mcp.company_tools.requests.post', side_effect=fake_post
        ):
            called = self._call(
                'ai_call_company_tool',
                {
                    'company_id': str(company_id),
                    'tool': 'identity_create_invitations',
                    'arguments': {'email': 'ada@example.com'},
                },
            )
        self.assertFalse(called.json()['result'].get('isError'), called.content)
        body = called.json()['result']['content'][0]['text']
        self.assertNotIn('Call ai_get_approval', body)
        self.assertIn('ai_call_company_tool', body)
        self.assertIn('same company_id, tool, and arguments', body)

    def test_company_catalog_keeps_ai_get_approval_name(self):
        from apps.connector import mcp_approval_copy as regional
        from apps.global_mcp.copy import rewrite_relayed_approval_copy

        description = regional.pending_agent_instruction(tool_name='identity_create_invitations')
        catalog = {
            'result': {
                'matches': [{'name': 'ai_get_approval', 'description': description}],
                'tools': [{'name': 'ai_get_approval', 'description': description}],
                'content': [
                    {
                        'type': 'text',
                        'text': 'ai_get_approval: Call ai_get_approval once with this approval_id (SSE holds until decided).',
                    }
                ],
                'isError': False,
            }
        }
        self.assertEqual(rewrite_relayed_approval_copy(catalog), catalog)

        company_id = uuid.uuid4()
        company = {
            'id': str(company_id),
            'role': 'owner',
            'regional_company_id': '42',
            'limits_version': 1,
            'status': 'active',
            'region': {'code': 'ch', 'ai_url': 'http://ai.region', 'identity_url': 'http://id.region'},
        }
        maybe_setup_grant(self.agent, company)

        def fake_post(url, json=None, headers=None, timeout=None):
            class Response:
                status_code = 200
                headers = {'Content-Type': 'application/json'}
                text = ''

                def json(self):
                    if str(url).endswith('/oauth/mcp/token'):
                        return {'access_token': 'regional-access', 'expires_in': 300, 'token_type': 'Bearer'}
                    name = (json or {}).get('params', {}).get('name')
                    entry = {'name': 'ai_get_approval', 'description': description}
                    if name == 'ai_search_tools':
                        return {'result': {'matches': [entry], 'isError': False}}
                    return {'result': {'tools': [entry], 'isError': False}}

            return Response()

        with patch('apps.global_mcp.company_tools.fetch_company', return_value=company), patch(
            'apps.global_mcp.company_tools.requests.post', side_effect=fake_post
        ):
            searched = self._call(
                'ai_company_search_tools',
                {'company_id': str(company_id), 'query': 'approval'},
            )
            described = self._call(
                'ai_company_describe_tool',
                {'company_id': str(company_id), 'names': ['ai_get_approval']},
            )
        self.assertFalse(searched.json()['result'].get('isError'), searched.content)
        search_body = json.loads(searched.json()['result']['content'][0]['text'])
        self.assertEqual(search_body['result']['matches'][0]['name'], 'ai_get_approval')
        self.assertEqual(search_body['result']['matches'][0]['description'], description)
        self.assertFalse(described.json()['result'].get('isError'), described.content)
        describe_body = json.loads(described.json()['result']['content'][0]['text'])
        self.assertEqual(describe_body['result']['tools'][0]['name'], 'ai_get_approval')
        self.assertEqual(describe_body['result']['tools'][0]['description'], description)

    def test_subject_token_version_and_single_use_jti(self):
        company_id = str(uuid.uuid4())
        first, claims_a = issue_subject_token(
            self.agent,
            global_company_id=company_id,
            binding_version=4,
            services=['ai', 'identity'],
            access_mode='ask',
            read_level='safe',
            destructive=False,
        )
        _second, claims_b = issue_subject_token(
            self.agent,
            global_company_id=company_id,
            binding_version=4,
            services=['ai', 'identity'],
            access_mode='ask',
            read_level='safe',
            destructive=False,
        )
        decoded = jwt.decode(first, _PUBLIC, algorithms=['RS256'], audience='shellui-agents', issuer='http://ai.test')
        self.assertEqual(decoded['company_binding_version'], 4)
        self.assertEqual(decoded['grant_version'], 4)
        self.assertEqual(decoded['mcp_authority'], 'global_delegated')
        self.assertEqual(decoded['token_type'], 'agent_access')
        self.assertNotEqual(claims_a['jti'], claims_b['jti'])
        self.assertNotIn(first, json.dumps(list(McpCallLog.objects.values_list('arguments_redacted', flat=True))))

    def test_narrow_grant_bumps_version_and_asks_saas_to_fan_out(self):
        company_id = uuid.uuid4()
        grant = GlobalAgentCompanyGrant.objects.create(
            agent=self.agent,
            global_company_id=company_id,
            regional_company_id='42',
            region_code='ch',
            services=['ai', 'identity', 'storage'],
            max_access_mode='ask',
            max_read_level='safe',
            max_destructive=False,
            binding_version=5,
        )
        requested = normalize_grant_request({'services': ['ai', 'identity'], 'access_mode': 'read_only'}, self.agent)
        with patch('apps.global_mcp.grants.request_json', return_value=(202, {})) as fanout:
            updated = narrow_grant(grant, requested)
        self.assertEqual(updated.binding_version, 6)
        self.assertEqual(fanout.call_args.args[0], 'POST')
        self.assertEqual(fanout.call_args.args[1], '/api/v1/internal/ai-global/revoke')
        self.assertEqual(fanout.call_args.kwargs['body']['binding_version'], 6)

    def test_wait_for_company_stops_on_active(self):
        company_id = str(uuid.uuid4())
        states = iter(
            [
                {'id': company_id, 'status': 'provisioning'},
                {'id': company_id, 'status': 'active', 'role': 'owner'},
            ]
        )
        with patch('apps.global_mcp.company_tools.fetch_company', side_effect=lambda *_a, **_k: next(states)), override_settings(
            GLOBAL_COMPANY_WAIT_SECONDS=5, GLOBAL_COMPANY_POLL_SECONDS=0.01
        ):
            result = self._call('ai_wait_for_company', {'company_id': company_id})
        body = json.loads(result.json()['result']['content'][0]['text'])
        self.assertEqual(body['status'], 'active')
        self.assertFalse(body['timed_out'])

    def test_approved_saas_token_carries_delegated_grant(self):
        from apps.global_mcp.tokens import issue_saas_api_token

        _token, claims = issue_saas_api_token(self.agent, delegated_action='saas_get_me')
        grant = claims['mcp_gateway_delegated']
        self.assertEqual(grant['action'], 'saas_get_me')
        self.assertLessEqual(int(grant['exp']) - int(claims['iat']), 60)
        self.assertGreater(int(grant['exp']), int(claims['iat']))

    def test_revocation_hook_error_is_forbidden(self):
        with patch(
            'apps.global_mcp.mcp_views.global_agent_revocation_check',
            side_effect=RuntimeError('down'),
        ):
            response = self.client.post(
                '/mcp',
                data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self.token}',
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['error'], 'revocation_unavailable')


class RegionUnchangedTests(TestCase):
    def test_plain_mcp_points_shellui_accounts_at_the_global_url(self):
        response = self.client.post('/mcp', data='{}', content_type='application/json')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()['error'], 'company_required')
        self.assertIn('Shellui account? Use https://ai.shellui.com/mcp.', response.json()['message'])

    def test_correlation_header_is_stored_only_for_global_delegated_calls(self):
        correlation = uuid.uuid4()

        class Request:
            headers = {'X-Shellui-Correlation-Id': str(correlation)}
            META = {}

        delegated = {
            'grant_version': 2,
            'company_binding_version': 2,
            'global_company_id': str(uuid.uuid4()),
            'agent_id': 'agent-1',
            'company_id': 10,
        }
        self.assertEqual(correlation_from_request(Request(), delegated), str(correlation))
        self.assertEqual(correlation_from_request(Request(), {'agent_id': 'agent-1', 'company_id': 10}), '')
        persist_mcp_call(
            {
                'company_id': 10,
                'tool': 'identity_list_users',
                'service': 'identity',
                'outcome': 'allowed',
                'status': 200,
                'agent_claims': delegated,
                'correlation_id': str(correlation),
            }
        )
        row = McpCallLog.objects.get(tool_name='identity_list_users')
        self.assertEqual(row.correlation_id, correlation)
        self.assertEqual(row.plane, 'region')


class QuotedJwksTests(TestCase):
    def test_one_pair_of_wrapping_quotes_is_removed(self):
        from config.settings import _strip_wrapped_quotes

        raw = '\'{"keys":[{"kty":"RSA"}]}\''
        self.assertEqual(_strip_wrapped_quotes(raw), '{"keys":[{"kty":"RSA"}]}')
        self.assertEqual(_strip_wrapped_quotes('{"keys":[]}'), '{"keys":[]}')


class ModeCheckTests(TestCase):
    @override_settings(AI_SERVICE_MODE='global', REGION_IDENTITY_CONFIGURED=True)
    def test_global_refuses_regional_identity_settings(self):
        ids = [item.id for item in run_checks() if item.id and item.id.startswith('ai_service.')]
        self.assertIn('ai_service.E001', ids)

    @override_settings(AI_SERVICE_MODE='region', GLOBAL_CONTROL_CONFIGURED=True)
    def test_region_refuses_global_authorization_settings(self):
        ids = [item.id for item in run_checks() if item.id and item.id.startswith('ai_service.')]
        self.assertIn('ai_service.E002', ids)


def _exchange_response():
    class Response:
        status_code = 200
        headers = {'Content-Type': 'application/json'}

        def json(self):
            return {'access_token': 'regional-access', 'expires_in': 300, 'token_type': 'Bearer'}

    return Response()
