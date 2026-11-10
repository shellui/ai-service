from django.test import SimpleTestCase

from apps.connector.mcp_tool_naming import (
    canonical_downstream_tool_name,
    gateway_export_name,
    legacy_slug_tool_name,
    published_upstream_tool_name,
    resolve_mcp_tool_name,
    select_newest_api_version_operations,
    service_local_tool_name,
    validate_tool_name,
    clamp_tool_name,
)


class McpToolNamingTests(SimpleTestCase):
    def test_legacy_slug(self):
        self.assertEqual(
            legacy_slug_tool_name('get', '/api/v1/templates/', 'api_v1_templates_list'),
            'api_v1_templates_list',
        )

    def test_clean_names(self):
        op = {'operationId': 'api_v1_actions_rules_create', 'tags': ['mcp-tools']}
        self.assertEqual(
            resolve_mcp_tool_name(op, 'post', '/api/v1/actions/rules/'),
            'create_action_rules',
        )
        op = {'operationId': 'api_v1_users_list', 'tags': ['mcp-tools']}
        self.assertEqual(resolve_mcp_tool_name(op, 'get', '/api/v1/users/'), 'list_users')
        op = {'operationId': 'api_v1_mcp_services_list', 'tags': ['mcp-tools']}
        self.assertEqual(resolve_mcp_tool_name(op, 'get', '/api/v1/mcp/services/'), 'list_services')

    def test_disambiguate_events_and_put_update(self):
        actions = {'operationId': 'api_v1_actions_events_list', 'tags': ['mcp-tools']}
        audit = {'operationId': 'api_v1_events_list', 'tags': ['mcp-tools']}
        self.assertEqual(
            resolve_mcp_tool_name(actions, 'get', '/api/v1/actions/events/'),
            'list_action_events',
        )
        self.assertEqual(resolve_mcp_tool_name(audit, 'get', '/api/v1/events/'), 'list_events')
        put = {'operationId': 'api_v1_auth_methods_update', 'tags': ['mcp-tools']}
        patch = {'operationId': 'api_v1_auth_methods_partial_update', 'tags': ['mcp-tools']}
        self.assertEqual(
            resolve_mcp_tool_name(put, 'put', '/api/v1/auth/methods/'),
            'replace_auth_methods',
        )
        self.assertEqual(
            resolve_mcp_tool_name(patch, 'patch', '/api/v1/auth/methods/'),
            'update_auth_methods',
        )

    def test_revoke_and_rotate_names(self):
        op = {'operationId': 'api_v1_invitations_revoke', 'tags': ['mcp-tools']}
        self.assertEqual(resolve_mcp_tool_name(op, 'post', '/api/v1/invitations/revoke/'), 'revoke_invitations')
        op = {'operationId': 'api_v1_actions_rules_rotate_secret', 'tags': ['mcp-tools']}
        self.assertEqual(
            resolve_mcp_tool_name(op, 'post', '/api/v1/actions/rules/rotate-secret/'),
            'rotate_rule_secret',
        )

    def test_gateway_prefix(self):
        self.assertEqual(gateway_export_name('email', 'send_message'), 'email_send_message')

    def test_canonical_legacy_downstream_name(self):
        self.assertEqual(
            canonical_downstream_tool_name('api_v1_actions_deliveries_list'),
            'list_deliveries',
        )
        self.assertEqual(
            canonical_downstream_tool_name('identity_api_v1_users_list', service_id='identity'),
            'list_users',
        )
        self.assertEqual(
            canonical_downstream_tool_name('update_auth_methods_2', service_id='identity'),
            'replace_auth_methods',
        )
        self.assertEqual(
            service_local_tool_name(
                {
                    'name': 'update_auth_methods_2',
                    '_meta': {
                        'operationId': 'api_v1_auth_methods_update',
                        'path': '/api/v1/auth/methods/',
                        'method': 'PUT',
                    },
                },
                service_id='identity',
            ),
            'replace_auth_methods',
        )

    def test_stripped_meta_storage_slug_uses_operation_id_and_path(self):
        """Downstream tools/list omits _meta; the tool name is the operation id slug."""
        tool = {
            'name': 'storage_v1_bucket_list',
            '_meta': {'path': '/storage/v1/bucket', 'method': 'GET'},
        }
        self.assertEqual(service_local_tool_name(tool, service_id='storage'), 'list_bucket')
        public_object = {
            'name': 'storage_v1_object_retrieve',
            '_meta': {'path': '/storage/v1/object/{bucket_id}/{object_path}', 'method': 'GET'},
        }
        self.assertEqual(service_local_tool_name(public_object, service_id='storage'), 'get_public_object')
        actions = {
            'name': 'api_v1_actions_events_list',
            '_meta': {'path': '/api/v1/actions/events', 'method': 'GET'},
        }
        self.assertEqual(service_local_tool_name(actions, service_id='identity'), 'list_action_events')

    def test_published_upstream_name_is_distinct_from_operation_id_slugs(self):
        self.assertTrue(published_upstream_tool_name('identity_create_groups', 'identity'))
        self.assertTrue(published_upstream_tool_name('storage_list_bucket', 'storage'))
        self.assertFalse(published_upstream_tool_name('api_v1_groups_create', 'identity'))
        self.assertFalse(published_upstream_tool_name('storage_v1_bucket_list', 'storage'))
        self.assertFalse(published_upstream_tool_name('hosting_v1_apps_list', 'hosting'))

    def test_published_name_that_disagrees_with_operation_is_dropped(self):
        from apps.connector.mcp_tool_schema import normalize_mcp_tool
        from apps.connector.mcp_views import iter_gateway_remote_exports

        tool = normalize_mcp_tool(
            {
                'name': 'identity_create_groups',
                'description': 'Create a manual group for the company.',
                'operationId': 'api_v1_users_list',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'path': {'type': 'string', 'const': '/api/v1/users'},
                        'method': {'type': 'string', 'enum': ['GET']},
                    },
                    'required': ['path', 'method'],
                    'additionalProperties': False,
                },
            }
        )
        self.assertEqual(iter_gateway_remote_exports([tool], service_id='identity'), [])

    def test_published_name_is_kept_and_forwarded_as_is(self):
        from apps.connector.mcp_tool_schema import normalize_mcp_tool
        from apps.connector.mcp_views import iter_gateway_remote_exports

        tool = normalize_mcp_tool(
            {
                'name': 'identity_list_users',
                'description': 'List company users for the authenticated company.',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'path': {'type': 'string', 'const': '/api/v1/users'},
                        'method': {'type': 'string', 'enum': ['GET']},
                    },
                    'required': ['path', 'method'],
                    'additionalProperties': False,
                },
            }
        )
        rows = iter_gateway_remote_exports([tool], service_id='identity')
        self.assertEqual(len(rows), 1)
        export_name, _exported, route = rows[0]
        self.assertEqual(export_name, 'identity_list_users')
        self.assertEqual(route['downstream_name'], 'identity_list_users')

    def test_newest_api_version(self):
        schema = {
            'paths': {
                '/api/v1/widgets/': {'get': {'tags': ['mcp-tools'], 'operationId': 'api_v1_widgets_list'}},
                '/api/v2/widgets/': {'get': {'tags': ['mcp-tools'], 'operationId': 'api_v2_widgets_list'}},
            },
        }
        picked = select_newest_api_version_operations(schema)
        self.assertEqual(len(picked), 1)
        self.assertEqual(picked[0][0], '/api/v2/widgets/')

    def test_clamp(self):
        self.assertEqual(validate_tool_name(clamp_tool_name('a' * 80)), [])

    def test_published_operation_id_and_tool_name_are_not_prefixed_twice(self):
        listed = {'operationId': 'identity_list_users'}
        self.assertEqual(resolve_mcp_tool_name(listed, 'get', '/api/v1/users/'), 'list_users')
        self.assertEqual(
            gateway_export_name('identity', resolve_mcp_tool_name(listed, 'get', '/api/v1/users/')),
            'identity_list_users',
        )
        self.assertEqual(
            resolve_mcp_tool_name({'operationId': 'identity_get_scim_status'}, 'get', '/api/v1/scim/status/'),
            'get_scim_status',
        )
        self.assertEqual(
            resolve_mcp_tool_name(
                {'operationId': 'identity_rotate_rule_secret'},
                'post',
                '/api/v1/actions/rules/rotate-secret/',
            ),
            'rotate_rule_secret',
        )
        email = {
            'operationId': 'api_v1_newsletters_create',
            'x-mcp': {'tool_name': 'email_create_newsletters'},
        }
        self.assertEqual(resolve_mcp_tool_name(email, 'post', '/api/v1/newsletters/'), 'create_newsletters')
        hosting = {
            'operationId': 'hosting_v1_apps_list',
            'x-mcp': {'tool_name': 'list_apps'},
        }
        self.assertEqual(resolve_mcp_tool_name(hosting, 'get', '/api/v1/apps/'), 'list_apps')
