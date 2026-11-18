"""A member lists call logs for an agent they own. Other members get 404."""

from __future__ import annotations

import time
from datetime import timedelta

import jwt
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.authapi.principal import StoragePrincipal
from apps.connector.mcp_call_store import owner_user_id_from_claims, persist_mcp_call, reset_gateway_tool_call
from apps.connector.models import McpCallLog

_PATH = '/ai/v1/mcp/personal/agents/{agent_id}/call-logs'


class PersonalAgentCallLogApiTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.other_owner_marker = 'other-owner-row'
        self.owned = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-a',
            agent_name='Ada',
            token_kind='personal',
            service='storage',
            tool_name='storage_list_buckets',
            wrapper_tool='',
            operation_title='List buckets',
            access_kind='read',
            outcome='allowed',
            resource_label='storage_list_buckets',
            arguments_redacted={'api_key': '***', 'name': 'Ada'},
            status='allowed',
            status_code=200,
            error_code='',
            error_message='',
            duration_ms=12,
            approval_channel='none',
            owner_user_id=7,
        )
        self.owned_older = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-a',
            agent_name='Ada',
            service='ai',
            tool_name='ai_search_tools',
            status='failed',
            status_code=200,
            error_code='mcp_tool_error',
            error_message='tool failed',
            approval_channel='form',
            approval_outcome='approved',
            outcome='failed',
            access_kind='read',
            operation_title='Search tools',
            resource_label='ai_search_tools',
            arguments_redacted={},
            owner_user_id=7,
        )
        self.same_agent_other_owner = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-a',
            service='email',
            tool_name='email_list_messages',
            status='allowed',
            status_code=200,
            approval_channel='none',
            arguments_redacted={'note': self.other_owner_marker},
            owner_user_id=8,
        )
        self.other_agent = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-b',
            service='storage',
            tool_name='storage_list_buckets',
            status='allowed',
            status_code=200,
            approval_channel='none',
            owner_user_id=8,
        )
        self.other_company = McpCallLog.objects.create(
            company_id=11,
            agent_id='agent-a',
            service='storage',
            tool_name='storage_list_buckets',
            status='allowed',
            status_code=200,
            approval_channel='none',
            owner_user_id=9,
        )
        self.legacy = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-legacy',
            service='storage',
            tool_name='storage_list_buckets',
            status='allowed',
            status_code=200,
            approval_channel='none',
            user_id=7,
            owner_user_id=None,
        )
        self.unattributed = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-blank',
            service='ai',
            tool_name='ai_list_services',
            status='allowed',
            status_code=200,
            approval_channel='none',
            user_id=None,
            owner_user_id=None,
        )
        self.owner_wins = McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-owner-wins',
            service='ai',
            tool_name='ai_list_services',
            status='allowed',
            status_code=200,
            approval_channel='none',
            user_id=7,
            owner_user_id=8,
        )
        McpCallLog.objects.filter(pk=self.owned.pk).update(created_at=now - timedelta(hours=1))
        McpCallLog.objects.filter(pk=self.owned_older.pk).update(created_at=now - timedelta(days=2))
        self.owned.refresh_from_db()
        self.owned_older.refresh_from_db()
        self.client = APIClient()

    def _auth(self, *, user_id=7, company_id=10, staff=False, owner=False, admin=False):
        self.client.force_authenticate(
            user=StoragePrincipal(
                user_id=user_id,
                company_id=company_id,
                email='member@example.com',
                is_staff=staff,
                is_company_owner=owner,
                is_company_admin=admin,
            )
        )

    def _get(self, agent_id='agent-a', **params):
        return self.client.get(_PATH.format(agent_id=agent_id), params)

    def test_owner_sees_own_rows_with_redacted_arguments(self):
        self._auth()
        listed = self._get()
        self.assertEqual(listed.status_code, 200, listed.content)
        body = listed.json()
        self.assertEqual(body['count'], 2)
        self.assertEqual(body['limit'], 50)
        self.assertEqual(body['offset'], 0)
        self.assertEqual([row['tool_name'] for row in body['call_logs']], ['storage_list_buckets', 'ai_search_tools'])
        newest = body['call_logs'][0]
        self.assertEqual(newest['arguments'], {'api_key': '***', 'name': 'Ada'})
        self.assertNotIn('arguments_redacted', newest)
        self.assertNotIn(self.other_owner_marker, listed.content.decode())
        self.assertEqual(newest['operation_title'], 'List buckets')
        self.assertEqual(newest['access_kind'], 'read')
        self.assertEqual(newest['outcome'], 'allowed')
        self.assertEqual(newest['resource_label'], 'storage_list_buckets')
        self.assertEqual(newest['status_code'], 200)
        self.assertEqual(newest['error_code'], '')
        self.assertEqual(newest['error_message'], '')
        self.assertEqual(newest['duration_ms'], 12)
        self.assertEqual(newest['approval_channel'], 'none')
        self.assertEqual(newest['wrapper_tool'], '')
        self.assertNotIn('owner_user_id', newest)
        self.assertNotIn('agent_audit_scope', newest)
        older = body['call_logs'][1]
        self.assertEqual(older['error_code'], 'mcp_tool_error')
        self.assertEqual(older['error_message'], 'tool failed')
        self.assertEqual(older['approval_channel'], 'form')
        self.assertEqual(older['approval_outcome'], 'approved')

    def test_plain_member_matches_admin_row_and_admin_list_stays_company_wide(self):
        self._auth(owner=True)
        personal = self._get().json()['call_logs'][0]
        admin = self.client.get('/ai/v1/mcp/call-logs', {'agent': 'agent-a', 'tool': 'storage_list_buckets'})
        self.assertEqual(admin.status_code, 200, admin.content)
        admin_row = admin.json()['call_logs'][0]
        self.assertEqual(personal, admin_row)
        company = self.client.get('/ai/v1/mcp/call-logs')
        tools = {row['tool_name'] for row in company.json()['call_logs']}
        self.assertIn('email_list_messages', tools)
        self._auth(owner=False, admin=False, staff=False)
        self.assertEqual(self.client.get('/ai/v1/mcp/call-logs').status_code, 403)
        self.assertEqual(self._get().status_code, 200)

    def test_same_company_other_user_is_404(self):
        self._auth(user_id=9, company_id=10)
        missing = self._get('agent-a')
        self.assertEqual(missing.status_code, 404, missing.content)
        self.assertEqual(missing.json(), {'error': 'Not found.'})
        self.assertNotIn('storage_list_buckets', missing.content.decode())
        self.assertNotIn(self.other_owner_marker, missing.content.decode())
        self._auth(user_id=8, company_id=10)
        shared = self._get('agent-a')
        self.assertEqual(shared.status_code, 200, shared.content)
        self.assertEqual([row['tool_name'] for row in shared.json()['call_logs']], ['email_list_messages'])
        self.assertNotIn('storage_list_buckets', shared.content.decode())

    def test_other_company_is_404(self):
        self._auth(user_id=12, company_id=11)
        missing = self._get('agent-a')
        self.assertEqual(missing.status_code, 404, missing.content)
        self.assertEqual(missing.json(), {'error': 'Not found.'})
        self._auth(user_id=7, company_id=11)
        switched = self._get('agent-a')
        self.assertEqual(switched.status_code, 404, switched.content)
        self.assertNotIn('storage_list_buckets', switched.content.decode())
        self._auth(user_id=9, company_id=11)
        own = self._get('agent-a')
        self.assertEqual(own.status_code, 200, own.content)
        self.assertEqual(own.json()['count'], 1)
        self.assertEqual(own.json()['call_logs'][0]['company_id'], 11)

    def test_staff_and_company_admin_have_no_extra_access(self):
        self._auth(user_id=99, staff=True, owner=True, admin=True)
        missing = self._get('agent-a')
        self.assertEqual(missing.status_code, 404, missing.content)
        self._auth(user_id=7, staff=True, owner=True, admin=True)
        self.assertEqual(self._get().status_code, 200)

    def test_legacy_user_id_is_owner_until_owner_user_id_is_set(self):
        self._auth()
        legacy = self._get('agent-legacy')
        self.assertEqual(legacy.status_code, 200, legacy.content)
        self.assertEqual(legacy.json()['count'], 1)
        self.assertEqual(legacy.json()['call_logs'][0]['user_id'], 7)
        blank = self._get('agent-blank')
        self.assertEqual(blank.status_code, 404, blank.content)
        claimed = self._get('agent-owner-wins')
        self.assertEqual(claimed.status_code, 404, claimed.content)
        self._auth(user_id=8)
        self.assertEqual(self._get('agent-owner-wins').status_code, 200)
        self.assertEqual(self._get('agent-legacy').status_code, 404)

    def test_filters_pagination_and_path_agent(self):
        self._auth()
        self.assertEqual(self._get(service='storage').json()['count'], 1)
        self.assertEqual(self._get(tool='ai_search_tools').json()['call_logs'][0]['tool_name'], 'ai_search_tools')
        self.assertEqual(self._get(status='failed').json()['count'], 1)
        after = (self.owned_older.created_at + timedelta(hours=1)).isoformat()
        ranged = self._get(created_after=after)
        self.assertEqual(ranged.json()['count'], 1)
        self.assertEqual(ranged.json()['call_logs'][0]['tool_name'], 'storage_list_buckets')
        before = self.owned.created_at.isoformat()
        self.assertEqual(self._get(created_before=before).json()['count'], 1)
        page = self._get(limit=1, offset=1)
        self.assertEqual(page.json()['count'], 2)
        self.assertEqual(page.json()['limit'], 1)
        self.assertEqual(page.json()['offset'], 1)
        self.assertEqual(page.json()['call_logs'][0]['tool_name'], 'ai_search_tools')
        empty = self._get(service='hosting')
        self.assertEqual(empty.status_code, 200, empty.content)
        self.assertEqual(empty.json()['count'], 0)
        self.assertEqual(empty.json()['call_logs'], [])
        ignored = self._get(agent='agent-b')
        self.assertEqual(ignored.status_code, 200, ignored.content)
        self.assertEqual({row['agent_id'] for row in ignored.json()['call_logs']}, {'agent-a'})
        self.assertEqual(self._get(status='nope').status_code, 400)
        self.assertEqual(self._get(limit=0).status_code, 400)
        self.assertEqual(self._get(limit=201).status_code, 400)
        self.assertEqual(self._get(offset=-1).status_code, 400)
        self.assertEqual(self._get(created_after='yesterday').status_code, 400)
        self.assertEqual(self._get('a' * 129).status_code, 404)

    def test_global_company_fields_match_the_admin_row(self):
        McpCallLog.objects.create(
            company_id=10,
            agent_id='agent-g',
            service='identity',
            tool_name='identity_list_users',
            operation_title='List users',
            access_kind='read',
            outcome='session_used',
            resource_label='GET /api/v1/users/',
            status='allowed',
            status_code=200,
            global_agent_id='33333333-3333-4333-8333-333333333333',
            global_company_id='22222222-2222-4222-8222-222222222222',
            owner_user_id=7,
        )
        self._auth()
        row = self._get('agent-g').json()['call_logs'][0]
        self.assertEqual(row['agent_audit_scope'], 'global_company')
        self.assertEqual(row['global_agent_id'], '33333333-3333-4333-8333-333333333333')
        self.assertEqual(row['global_company_id'], '22222222-2222-4222-8222-222222222222')
        self.assertEqual(row['outcome'], 'session_used')

    def test_missing_auth_is_401(self):
        self.assertEqual(self._get().status_code, 401)
        self.client.force_authenticate(user=None)
        self.assertEqual(self._get().status_code, 401)

    @override_settings(
        DEBUG=True,
        JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',  # gitleaks:allow
        ALLOW_JWT_HS256_FALLBACK=True,
        IDENTITY_ISSUER='',
        IDENTITY_AUDIENCE='',
        IDENTITY_JWKS_URL='',
    )
    def test_agent_token_is_refused(self):
        now = int(time.time())
        token = jwt.encode(
            {
                'token_type': 'access',
                'sub': 'agent:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                'agent_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                'company_id': 10,
                'owner_user_id': 7,
                'scope': 'ai',
                'iat': now,
                'exp': now + 600,
            },
            'test-hs256-secret-for-mcp-gateway-tests-only',  # gitleaks:allow
            algorithm='HS256',
        )
        client = APIClient()
        response = client.get(_PATH.format(agent_id='agent-a'), HTTP_AUTHORIZATION=f'Bearer {token}')
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(self.other_owner_marker, response.content.decode())
        self.client.force_authenticate(
            user=StoragePrincipal(
                user_id=0,
                company_id=10,
                username='agent:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                claims={
                    'sub': 'agent:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'agent_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'owner_user_id': 7,
                },
            )
        )
        self.assertEqual(self._get().status_code, 403)


class OwnerUserIdWriteTests(TestCase):
    def test_claim_parser_accepts_a_positive_integer_only(self):
        self.assertEqual(owner_user_id_from_claims({'owner_user_id': 7}), 7)
        self.assertEqual(owner_user_id_from_claims({'owner_user_id': '7'}), 7)
        self.assertEqual(owner_user_id_from_claims({'owner_user_id': ' 8 '}), 8)
        self.assertIsNone(owner_user_id_from_claims({'owner_user_id': True}))
        self.assertIsNone(owner_user_id_from_claims({'owner_user_id': False}))
        self.assertIsNone(owner_user_id_from_claims({'owner_user_id': 0}))
        self.assertIsNone(owner_user_id_from_claims({'owner_user_id': -3}))
        self.assertIsNone(owner_user_id_from_claims({'owner_user_id': 7.5}))
        self.assertIsNone(owner_user_id_from_claims({'owner_user_id': '7abc'}))
        self.assertIsNone(owner_user_id_from_claims({'user_id': 7}))
        self.assertIsNone(owner_user_id_from_claims(None))

    def test_persist_reads_owner_from_claims_and_ignores_the_entry(self):
        reset_gateway_tool_call()
        persist_mcp_call(
            {
                'company_id': 10,
                'tool': 'ai_list_services',
                'outcome': 'allowed',
                'status': 200,
                'owner_user_id': 99,
                'arguments': {'owner_user_id': 99, 'api_key': 'sekret-value'},
                'agent_claims': {'agent_id': 'agent-a', 'company_id': 10, 'user_id': 4},
            }
        )
        row = McpCallLog.objects.get()
        self.assertIsNone(row.owner_user_id)
        self.assertEqual(row.user_id, 4)
        self.assertEqual(row.arguments_redacted['api_key'], '***')
        self.assertNotIn('sekret-value', str(row.arguments_redacted))

        reset_gateway_tool_call()
        McpCallLog.objects.all().delete()
        persist_mcp_call(
            {
                'company_id': 10,
                'tool': 'ai_list_services',
                'outcome': 'allowed',
                'status': 200,
                'arguments': {'owner_user_id': 99},
                'agent_claims': {'agent_id': 'agent-a', 'company_id': 10, 'owner_user_id': '7'},
            }
        )
        stored = McpCallLog.objects.get()
        self.assertEqual(stored.owner_user_id, 7)
        self.assertIsNone(stored.user_id)
