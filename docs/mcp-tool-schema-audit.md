# MCP tool inputSchema audit (all services)

Generated from each service OpenAPI document (`mcp-tools` operations) using the
legacy shellui-django 0.4.0 converter (**before**) and the ai-service typed converter
+ normalization (**after**). Aligns with MCP Inspector checks (validation keywords,
combinators, refs, nullable type arrays, required query/body fields).

## Summary counts

| Service | Tools | Issues before | Issues after |
| --- | ---: | ---: | ---: |
| ai | 1 | 2 | 0 |
| email | 65 | 272 | 0 |
| hosting | 29 | 120 | 0 |
| identity | 62 | 320 | 0 |
| saas | 0 | 0 | 0 |
| storage | 44 | 222 | 0 |
| **Total** | **201** | **936** | **0** |

### By category (before → after)

- `missing_annotations`: 201 → 0
- `missing_description`: 296 → 0
- `missing_title`: 201 → 0
- `untyped_or_empty`: 187 → 0
- `vague_tool_metadata`: 51 → 0

## Tool presentation coverage

| Service | Tools | Title | Description | Annotations | Output schema | Input props described |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ai | 1 | 1/1 | 1/1 | 1/1 | 0/1 | 2/2 |
| email | 65 | 65/65 | 65/65 | 65/65 | 56/65 | 349/349 |
| hosting | 29 | 29/29 | 29/29 | 29/29 | 27/29 | 139/139 |
| identity | 62 | 62/62 | 62/62 | 62/62 | 4/62 | 346/346 |
| storage | 44 | 44/44 | 44/44 | 44/44 | 28/44 | 238/238 |


## Tool name mapping (legacy → service → gateway)

Legacy names are slugified `operationId` values (pre–shellui-django 0.4.2). Service names
use `<verb>_<noun>` without `api/v1` segments. The ai gateway exports every tool as
``{service}_{tool}`` (single underscore, including local ai tools). Full list: `name_mappings` in
`docs/mcp-tool-schema-audit.json`.

| Service | Legacy | Service tool | Gateway export |
| --- | --- | --- | --- |
| ai | `api_v1_mcp_services_list` | `list_services` | `ai_list_services` |
| identity | `api_v1_groups_create` | `create_groups` | `identity_create_groups` |
| identity | `api_v1_invitations_create` | `create_invitations` | `identity_create_invitations` |
| identity | `api_v1_oauth_clients_create` | `create_oauth_clients` | `identity_create_oauth_clients` |
| identity | `api_v1_oauth_redirects_create` | `create_oauth_redirects` | `identity_create_oauth_redirects` |
| identity | `api_v1_oauth_social_apps_create` | `create_oauth_social_apps` | `identity_create_oauth_social_apps` |
| identity | `api_v1_personal_access_tokens_create` | `create_personal_access_tokens` | `identity_create_personal_access_tokens` |
| identity | `api_v1_actions_rules_create` | `create_rules` | `identity_create_rules` |
| identity | `api_v1_scim_tokens_create` | `create_scim_tokens` | `identity_create_scim_tokens` |
| identity | `api_v1_groups_destroy` | `delete_groups` | `identity_delete_groups` |
| identity | `api_v1_hosting_oauth_redirects_destroy` | `delete_hosting_oauth_redirects` | `identity_delete_hosting_oauth_redirects` |
| identity | `api_v1_invitations_destroy` | `delete_invitations` | `identity_delete_invitations` |
| identity | `api_v1_oauth_clients_destroy` | `delete_oauth_clients` | `identity_delete_oauth_clients` |
| identity | `api_v1_oauth_redirects_destroy` | `delete_oauth_redirects` | `identity_delete_oauth_redirects` |
| identity | `api_v1_oauth_social_apps_destroy` | `delete_oauth_social_apps` | `identity_delete_oauth_social_apps` |
| identity | `api_v1_actions_rules_destroy` | `delete_rules` | `identity_delete_rules` |
| identity | `api_v1_users_destroy` | `delete_users` | `identity_delete_users` |
| identity | `api_v1_auth_methods_retrieve` | `get_auth_methods` | `identity_get_auth_methods` |
| identity | `api_v1_companies_retrieve` | `get_companies` | `identity_get_companies` |
| identity | `api_v1_actions_deliveries_retrieve` | `get_deliveries` | `identity_get_deliveries` |
| identity | `api_v1_events_retrieve` | `get_events` | `identity_get_events` |
| identity | `api_v1_events_retention_retrieve` | `get_events_retention` | `identity_get_events_retention` |
| identity | `api_v1_groups_retrieve` | `get_groups` | `identity_get_groups` |
| identity | `api_v1_oauth_clients_retrieve` | `get_oauth_clients` | `identity_get_oauth_clients` |
| identity | `api_v1_oauth_provider_catalog_retrieve` | `get_oauth_provider_catalog` | `identity_get_oauth_provider_catalog` |
| identity | `api_v1_oauth_redirects_retrieve` | `get_oauth_redirects` | `identity_get_oauth_redirects` |
| identity | `api_v1_actions_rules_retrieve` | `get_rules` | `identity_get_rules` |
| identity | `api_v1_users_retrieve` | `get_users` | `identity_get_users` |
| identity | `api_v1_invitations_revoke` | `invitations_revoke` | `identity_invitations_revoke` |
| identity | `api_v1_companies_list` | `list_companies` | `identity_list_companies` |
| identity | `api_v1_actions_deliveries_list` | `list_deliveries` | `identity_list_deliveries` |
| identity | `api_v1_actions_events_list` | `list_events` | `identity_list_events` |
| identity | `api_v1_events_list` | `list_events_2` | `identity_list_events_2` |
| identity | `api_v1_events_types_list` | `list_events_types` | `identity_list_events_types` |
| identity | `api_v1_groups_list` | `list_groups` | `identity_list_groups` |
| identity | `api_v1_invitations_list` | `list_invitations` | `identity_list_invitations` |
| identity | `api_v1_oauth_clients_list` | `list_oauth_clients` | `identity_list_oauth_clients` |
| identity | `api_v1_oauth_redirects_list` | `list_oauth_redirects` | `identity_list_oauth_redirects` |
| identity | `api_v1_oauth_social_apps_list` | `list_oauth_social_apps` | `identity_list_oauth_social_apps` |
| identity | `api_v1_personal_access_tokens_list` | `list_personal_access_tokens` | `identity_list_personal_access_tokens` |
| identity | `api_v1_actions_rules_list` | `list_rules` | `identity_list_rules` |
| identity | `api_v1_scim_tokens_list` | `list_scim_tokens` | `identity_list_scim_tokens` |
| identity | `api_v1_mcp_services_list` | `list_services` | `identity_list_services` |
| identity | `api_v1_users_list` | `list_users` | `identity_list_users` |
| identity | `api_v1_personal_access_tokens_revoke` | `personal_access_tokens_revoke` | `identity_personal_access_tokens_revoke` |
| identity | `api_v1_actions_deliveries_requeue` | `requeue_deliveries` | `identity_requeue_deliveries` |
| identity | `api_v1_actions_rules_rotate_secret` | `rotate_secret_rules` | `identity_rotate_secret_rules` |
| identity | `api_v1_scim_status` | `scim_status` | `identity_scim_status` |
| identity | `api_v1_scim_tokens_revoke` | `scim_tokens_revoke` | `identity_scim_tokens_revoke` |
| identity | `api_v1_actions_rules_send_test` | `send_test_rules` | `identity_send_test_rules` |
| identity | `api_v1_auth_methods_partial_update` | `update_auth_methods` | `identity_update_auth_methods` |
| identity | `api_v1_auth_methods_update` | `update_auth_methods_2` | `identity_update_auth_methods_2` |
| identity | `api_v1_companies_partial_update` | `update_companies` | `identity_update_companies` |
| identity | `api_v1_companies_update` | `update_companies_2` | `identity_update_companies_2` |
| identity | `api_v1_groups_partial_update` | `update_groups` | `identity_update_groups` |
| identity | `api_v1_groups_update` | `update_groups_2` | `identity_update_groups_2` |
| identity | `api_v1_hosting_oauth_redirects_update` | `update_hosting_oauth_redirects` | `identity_update_hosting_oauth_redirects` |
| identity | `api_v1_oauth_clients_update` | `update_oauth_clients` | `identity_update_oauth_clients` |
| identity | `api_v1_oauth_redirects_partial_update` | `update_oauth_redirects` | `identity_update_oauth_redirects` |
| identity | `api_v1_oauth_social_apps_update` | `update_oauth_social_apps` | `identity_update_oauth_social_apps` |
| identity | `api_v1_actions_rules_partial_update` | `update_rules` | `identity_update_rules` |
| identity | `api_v1_users_update` | `update_users` | `identity_update_users` |
| identity | `api_v1_users_audience` | `users_audience` | `identity_users_audience` |
| storage | `storage_v1_object_copy_create` | `copy_object` | `storage_copy_object` |
| storage | `storage_v1_access_grant_create` | `create_access_grant` | `storage_create_access_grant` |
| storage | `storage_v1_object_create` | `create_object` | `storage_create_object` |
| storage | `storage_v1_object_list_create` | `create_object_list` | `storage_create_object_list` |
| storage | `storage_v1_object_prefix_create` | `create_object_prefix` | `storage_create_object_prefix` |
| storage | `api_v1_actions_rules_create` | `create_rules` | `storage_create_rules` |
| storage | `storage_v1_share_create` | `create_share` | `storage_create_share` |
| storage | `storage_v1_access_grant_destroy` | `delete_access_grant` | `storage_delete_access_grant` |
| storage | `storage_v1_share_link_destroy` | `delete_link_share` | `storage_delete_link_share` |
| storage | `storage_v1_object_delete_many` | `delete_many_object` | `storage_delete_many_object` |
| storage | `storage_v1_object_destroy` | `delete_object` | `storage_delete_object` |
| storage | `storage_v1_object_prefix_destroy` | `delete_object_prefix` | `storage_delete_object_prefix` |
| storage | `api_v1_actions_rules_destroy` | `delete_rules` | `storage_delete_rules` |
| storage | `storage_v1_bucket_empty_create` | `empty_bucket` | `storage_empty_bucket` |
| storage | `storage_v1_bucket_retrieve` | `get_bucket` | `storage_get_bucket` |
| storage | `api_v1_actions_deliveries_retrieve` | `get_deliveries` | `storage_get_deliveries` |
| storage | `api_v1_actions_event_log_retrieve` | `get_event_log` | `storage_get_event_log` |
| storage | `api_v1_actions_event_log_retention_retrieve` | `get_event_log_retention` | `storage_get_event_log_retention` |
| storage | `storage_v1_object_authenticated_retrieve` | `get_object` | `storage_get_object` |
| storage | `storage_v1_object_retrieve` | `get_object_2` | `storage_get_object_2` |
| storage | `storage_v1_object_id_retrieve` | `get_object_id` | `storage_get_object_id` |
| storage | `storage_v1_object_info_authenticated_retrieve` | `get_object_info` | `storage_get_object_info` |
| storage | `storage_v1_object_prefix_retrieve` | `get_object_prefix` | `storage_get_object_prefix` |
| storage | `storage_v1_quota_retrieve` | `get_quota` | `storage_get_quota` |
| storage | `api_v1_actions_rules_retrieve` | `get_rules` | `storage_get_rules` |
| storage | `storage_v1_stats_retrieve` | `get_stats` | `storage_get_stats` |
| storage | `storage_v1_access_grant_list` | `list_access_grant` | `storage_list_access_grant` |
| storage | `storage_v1_bucket_list` | `list_bucket` | `storage_list_bucket` |
| storage | `api_v1_actions_deliveries_list` | `list_deliveries` | `storage_list_deliveries` |
| storage | `api_v1_actions_event_log_list` | `list_event_log` | `storage_list_event_log` |
| storage | `api_v1_actions_event_log_types_list` | `list_event_log_types` | `storage_list_event_log_types` |
| storage | `api_v1_actions_events_list` | `list_events` | `storage_list_events` |
| storage | `api_v1_actions_rules_list` | `list_rules` | `storage_list_rules` |
| storage | `storage_v1_share_list` | `list_share` | `storage_list_share` |
| storage | `storage_v1_object_move_create` | `move_object` | `storage_move_object` |
| storage | `api_v1_actions_deliveries_requeue` | `requeue_deliveries` | `storage_requeue_deliveries` |
| storage | `api_v1_actions_rules_rotate_secret` | `rotate_secret_rules` | `storage_rotate_secret_rules` |
| storage | `api_v1_actions_rules_send_test` | `send_test_rules` | `storage_send_test_rules` |
| storage | `storage_v1_object_sign_create` | `sign_object` | `storage_sign_object` |
| storage | `storage_v1_object_sign_path_create` | `sign_path_object` | `storage_sign_path_object` |
| storage | `storage_v1_object_update` | `update_object` | `storage_update_object` |
| storage | `storage_v1_quota_company_update` | `update_quota_company` | `storage_update_quota_company` |
| storage | `storage_v1_quota_company_user_update` | `update_quota_company_user` | `storage_update_quota_company_user` |
| storage | `api_v1_actions_rules_partial_update` | `update_rules` | `storage_update_rules` |
| hosting | `hosting_v1_access_request_create` | `create_access_request` | `hosting_create_access_request` |
| hosting | `hosting_v1_apps_create` | `create_apps` | `hosting_create_apps` |
| hosting | `hosting_v1_apps_deployments_create` | `create_apps_deployments` | `hosting_create_apps_deployments` |
| hosting | `hosting_v1_apps_deployments_finalize_create` | `create_apps_deployments_finalize` | `hosting_create_apps_deployments_finalize` |
| hosting | `hosting_v1_apps_deployments_rollback_create` | `create_apps_deployments_rollback` | `hosting_create_apps_deployments_rollback` |
| hosting | `hosting_v1_apps_renew_expiry_create` | `create_apps_renew_expiry` | `hosting_create_apps_renew_expiry` |
| hosting | `hosting_v1_deploy_tokens_revoke_create` | `create_deploy_tokens_revoke` | `hosting_create_deploy_tokens_revoke` |
| hosting | `hosting_v1_preview_create` | `create_preview` | `hosting_create_preview` |
| hosting | `api_v1_actions_rules_create` | `create_rules` | `hosting_create_rules` |
| hosting | `hosting_v1_apps_destroy` | `delete_apps` | `hosting_delete_apps` |
| hosting | `api_v1_actions_rules_destroy` | `delete_rules` | `hosting_delete_rules` |
| hosting | `hosting_v1_apps_retrieve` | `get_apps` | `hosting_get_apps` |
| hosting | `api_v1_actions_deliveries_retrieve` | `get_deliveries` | `hosting_get_deliveries` |
| hosting | `hosting_v1_deploy_tokens_retrieve` | `get_deploy_tokens` | `hosting_get_deploy_tokens` |
| hosting | `api_v1_actions_event_log_retrieve` | `get_event_log` | `hosting_get_event_log` |
| hosting | `api_v1_actions_event_log_retention_retrieve` | `get_event_log_retention` | `hosting_get_event_log_retention` |
| hosting | `api_v1_actions_rules_retrieve` | `get_rules` | `hosting_get_rules` |
| hosting | `hosting_v1_stats_retrieve` | `get_stats` | `hosting_get_stats` |
| hosting | `hosting_v1_apps_list` | `list_apps` | `hosting_list_apps` |
| hosting | `hosting_v1_apps_deployments_list` | `list_apps_deployments` | `hosting_list_apps_deployments` |
| hosting | `api_v1_actions_deliveries_list` | `list_deliveries` | `hosting_list_deliveries` |
| hosting | `api_v1_actions_event_log_list` | `list_event_log` | `hosting_list_event_log` |
| hosting | `api_v1_actions_event_log_types_list` | `list_event_log_types` | `hosting_list_event_log_types` |
| hosting | `api_v1_actions_events_list` | `list_events` | `hosting_list_events` |
| hosting | `api_v1_actions_rules_list` | `list_rules` | `hosting_list_rules` |
| hosting | `api_v1_actions_deliveries_requeue` | `requeue_deliveries` | `hosting_requeue_deliveries` |
| hosting | `api_v1_actions_rules_rotate_secret` | `rotate_secret_rules` | `hosting_rotate_secret_rules` |
| hosting | `api_v1_actions_rules_send_test` | `send_test_rules` | `hosting_send_test_rules` |
| hosting | `api_v1_actions_rules_partial_update` | `update_rules` | `hosting_update_rules` |
| email | `api_v1_broadcasts_preview` | `broadcasts_preview` | `email_broadcasts_preview` |
| email | `api_v1_broadcasts_send` | `broadcasts_send` | `email_broadcasts_send` |
| email | `api_v1_messages_cancel` | `cancel_messages` | `email_cancel_messages` |
| email | `api_v1_broadcasts_create` | `create_broadcasts` | `email_create_broadcasts` |
| email | `api_v1_library_create` | `create_library` | `email_create_library` |
| email | `api_v1_newsletters_create` | `create_newsletters` | `email_create_newsletters` |
| email | `api_v1_newsletters_subscribers_create` | `create_newsletters_subscribers` | `email_create_newsletters_subscribers` |
| email | `api_v1_actions_rules_create` | `create_rules` | `email_create_rules` |
| email | `api_v1_rules_create` | `create_rules_2` | `email_create_rules_2` |
| email | `api_v1_suppressions_create` | `create_suppressions` | `email_create_suppressions` |
| email | `api_v1_template_versions_create` | `create_template_versions` | `email_create_template_versions` |
| email | `api_v1_broadcasts_destroy` | `delete_broadcasts` | `email_delete_broadcasts` |
| email | `api_v1_library_destroy` | `delete_library` | `email_delete_library` |
| email | `api_v1_newsletters_destroy` | `delete_newsletters` | `email_delete_newsletters` |
| email | `api_v1_newsletters_subscribers_destroy` | `delete_newsletters_subscribers` | `email_delete_newsletters_subscribers` |
| email | `api_v1_actions_rules_destroy` | `delete_rules` | `email_delete_rules` |
| email | `api_v1_rules_destroy` | `delete_rules_2` | `email_delete_rules_2` |
| email | `api_v1_suppressions_destroy` | `delete_suppressions` | `email_delete_suppressions` |
| email | `api_v1_templates_destroy` | `delete_templates` | `email_delete_templates` |
| email | `api_v1_auth_link_hosts_retrieve` | `get_auth_link_hosts` | `email_get_auth_link_hosts` |
| email | `api_v1_broadcasts_retrieve` | `get_broadcasts` | `email_get_broadcasts` |
| email | `api_v1_catalog_retrieve` | `get_catalog` | `email_get_catalog` |
| email | `api_v1_actions_deliveries_retrieve` | `get_deliveries` | `email_get_deliveries` |
| email | `api_v1_actions_event_log_retrieve` | `get_event_log` | `email_get_event_log` |
| email | `api_v1_actions_event_log_retention_retrieve` | `get_event_log_retention` | `email_get_event_log_retention` |
| email | `api_v1_library_retrieve` | `get_library` | `email_get_library` |
| email | `api_v1_messages_retrieve` | `get_messages` | `email_get_messages` |
| email | `api_v1_newsletters_retrieve` | `get_newsletters` | `email_get_newsletters` |
| email | `api_v1_provider_retrieve` | `get_provider` | `email_get_provider` |
| email | `api_v1_actions_rules_retrieve` | `get_rules` | `email_get_rules` |
| email | `api_v1_rules_retrieve` | `get_rules_2` | `email_get_rules_2` |
| email | `api_v1_stats_retrieve` | `get_stats` | `email_get_stats` |
| email | `api_v1_template_versions_retrieve` | `get_template_versions` | `email_get_template_versions` |
| email | `api_v1_templates_retrieve` | `get_templates` | `email_get_templates` |
| email | `api_v1_broadcasts_list` | `list_broadcasts` | `email_list_broadcasts` |
| email | `api_v1_actions_deliveries_list` | `list_deliveries` | `email_list_deliveries` |
| email | `api_v1_actions_event_log_list` | `list_event_log` | `email_list_event_log` |
| email | `api_v1_actions_event_log_types_list` | `list_event_log_types` | `email_list_event_log_types` |
| email | `api_v1_actions_events_list` | `list_events` | `email_list_events` |
| email | `api_v1_library_list` | `list_library` | `email_list_library` |
| email | `api_v1_messages_list` | `list_messages` | `email_list_messages` |
| email | `api_v1_newsletters_list` | `list_newsletters` | `email_list_newsletters` |
| email | `api_v1_newsletters_subscribers_list` | `list_newsletters_subscribers` | `email_list_newsletters_subscribers` |
| email | `api_v1_actions_rules_list` | `list_rules` | `email_list_rules` |
| email | `api_v1_rules_list` | `list_rules_2` | `email_list_rules_2` |
| email | `api_v1_suppressions_list` | `list_suppressions` | `email_list_suppressions` |
| email | `api_v1_template_versions_list` | `list_template_versions` | `email_list_template_versions` |
| email | `api_v1_templates_list` | `list_templates` | `email_list_templates` |
| email | `api_v1_newsletters_rotate_key` | `newsletters_rotate_key` | `email_newsletters_rotate_key` |
| email | `api_v1_newsletters_subscribers_export` | `newsletters_subscribers_export` | `email_newsletters_subscribers_export` |
| email | `api_v1_newsletters_subscribers_import` | `newsletters_subscribers_import` | `email_newsletters_subscribers_import` |
| email | `api_v1_template_versions_publish` | `publish_template_versions` | `email_publish_template_versions` |
| email | `api_v1_templates_render_preview` | `render_preview_templates` | `email_render_preview_templates` |
| email | `api_v1_actions_deliveries_requeue` | `requeue_deliveries` | `email_requeue_deliveries` |
| email | `api_v1_actions_rules_rotate_secret` | `rotate_secret_rules` | `email_rotate_secret_rules` |
| email | `api_v1_actions_rules_send_test` | `send_test_rules` | `email_send_test_rules` |
| email | `api_v1_templates_send_test` | `send_test_templates` | `email_send_test_templates` |
| email | `api_v1_provider_test_send` | `test_send_provider` | `email_test_send_provider` |
| email | `api_v1_auth_link_hosts_update` | `update_auth_link_hosts` | `email_update_auth_link_hosts` |
| email | `api_v1_broadcasts_partial_update` | `update_broadcasts` | `email_update_broadcasts` |
| email | `api_v1_library_update` | `update_library` | `email_update_library` |
| email | `api_v1_newsletters_partial_update` | `update_newsletters` | `email_update_newsletters` |
| email | `api_v1_provider_update` | `update_provider` | `email_update_provider` |
| email | `api_v1_actions_rules_partial_update` | `update_rules` | `email_update_rules` |
| email | `api_v1_rules_partial_update` | `update_rules_2` | `email_update_rules_2` |


## Per-service, per-tool issues (after fix)

### ai

_No remaining issues._

### email

_No remaining issues._

### hosting

_No remaining issues._

### identity

_No remaining issues._

### saas

_No remaining issues._

### storage

_No remaining issues._

## Per-service, per-tool issues (before fix)

Machine-readable full dump: `docs/mcp-tool-schema-audit.json` (`before` / `after_gateway` arrays).
SaaS is omitted (no public `saas-service` checkout in this audit); **201** tools matches the
five audited services (identity, storage, hosting, email, ai gateway).

### ai (2 issues)
- **api_v1_mcp_services_list** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations

### email (272 issues)
- **api_v1_actions_deliveries_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_deliveries_requeue** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_deliveries_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_event_log_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_event_log_retention_retrieve** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_event_log_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_event_log_types_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_events_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_rules_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_rules_destroy** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_rules_partial_update** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_rotate_secret** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_send_test** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_auth_link_hosts_retrieve** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_auth_link_hosts_update** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_broadcasts_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_broadcasts_destroy** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.broadcast_id`: missing_description
- **api_v1_broadcasts_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_broadcasts_partial_update** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.broadcast_id`: missing_description
- **api_v1_broadcasts_preview** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.broadcast_id`: missing_description
- **api_v1_broadcasts_retrieve** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.broadcast_id`: missing_description
- **api_v1_broadcasts_send** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.broadcast_id`: missing_description
- **api_v1_catalog_retrieve** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **api_v1_library_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_library_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.library_id`: missing_description
- **api_v1_library_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_library_retrieve** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.library_id`: missing_description
- **api_v1_library_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.library_id`: missing_description
- **api_v1_messages_cancel** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.message_id`: missing_description
- **api_v1_messages_list** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.query.properties.lane`: untyped_or_empty
  - `properties.query.properties.limit`: untyped_or_empty
  - `properties.query.properties.status`: untyped_or_empty
  - `properties.query.properties.template_key`: untyped_or_empty
- **api_v1_messages_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.message_id`: missing_description
- **api_v1_newsletters_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_newsletters_destroy** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_newsletters_list** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_newsletters_partial_update** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_newsletters_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_newsletters_rotate_key** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_newsletters_subscribers_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_newsletters_subscribers_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
  - `properties.path_params.properties.subscriber_id`: missing_description
- **api_v1_newsletters_subscribers_export** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.status`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_newsletters_subscribers_import** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_newsletters_subscribers_list** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.email`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.status`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.newsletter_id`: missing_description
- **api_v1_provider_retrieve** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_provider_test_send** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_provider_update** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_rules_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_rules_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.rule_id`: missing_description
- **api_v1_rules_list** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.query.properties.service`: untyped_or_empty
- **api_v1_rules_partial_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.rule_id`: missing_description
- **api_v1_rules_retrieve** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.rule_id`: missing_description
- **api_v1_stats_retrieve** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
  - `properties.query.properties.from`: untyped_or_empty
  - `properties.query.properties.lane`: untyped_or_empty
  - `properties.query.properties.to`: untyped_or_empty
- **api_v1_suppressions_create** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_suppressions_destroy** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.suppression_id`: missing_description
- **api_v1_suppressions_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_template_versions_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description
- **api_v1_template_versions_list** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description
- **api_v1_template_versions_publish** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description
  - `properties.path_params.properties.number`: missing_description
- **api_v1_template_versions_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description
  - `properties.path_params.properties.number`: missing_description
- **api_v1_templates_destroy** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description
- **api_v1_templates_list** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
- **api_v1_templates_render_preview** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description
- **api_v1_templates_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description
- **api_v1_templates_send_test** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.template_id`: missing_description

### hosting (120 issues)
- **api_v1_actions_deliveries_list** (11 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.action_rule_id`: untyped_or_empty
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.query.properties.created_after`: untyped_or_empty
  - `properties.query.properties.created_before`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.scheduled_job_run_id`: untyped_or_empty
  - `properties.query.properties.status`: untyped_or_empty
- **api_v1_actions_deliveries_requeue** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_deliveries_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_event_log_list** (10 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.query.properties.created_after`: untyped_or_empty
  - `properties.query.properties.created_before`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.user`: untyped_or_empty
  - `properties.query.properties.user_id`: untyped_or_empty
- **api_v1_actions_event_log_retention_retrieve** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_event_log_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_event_log_types_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_events_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_rules_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_rules_destroy** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.company_id`: untyped_or_empty
- **api_v1_actions_rules_partial_update** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_rotate_secret** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_send_test** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **hosting_v1_access_request_create** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **hosting_v1_apps_create** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **hosting_v1_apps_deployments_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.app_ref`: missing_description
- **hosting_v1_apps_deployments_finalize_create** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.app_ref`: missing_description
  - `properties.path_params.properties.deployment_id`: missing_description
- **hosting_v1_apps_deployments_list** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.app_ref`: missing_description
- **hosting_v1_apps_deployments_rollback_create** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.app_ref`: missing_description
  - `properties.path_params.properties.deployment_id`: missing_description
- **hosting_v1_apps_destroy** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.app_ref`: missing_description
- **hosting_v1_apps_list** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **hosting_v1_apps_renew_expiry_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.app_ref`: missing_description
- **hosting_v1_apps_retrieve** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.app_ref`: missing_description
- **hosting_v1_deploy_tokens_retrieve** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **hosting_v1_deploy_tokens_revoke_create** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.token_id`: missing_description
- **hosting_v1_preview_create** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **hosting_v1_stats_retrieve** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations

### identity (320 issues)
- **api_v1_actions_deliveries_list** (13 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.action_rule_id`: untyped_or_empty
  - `properties.query.properties.created_after`: untyped_or_empty
  - `properties.query.properties.created_before`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.scheduled_job_run_id`: untyped_or_empty
  - `properties.query.properties.status`: untyped_or_empty
- **api_v1_actions_deliveries_requeue** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_deliveries_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_events_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_actions_rules_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_actions_rules_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_actions_rules_partial_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_rotate_secret** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_send_test** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_auth_methods_partial_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_auth_methods_retrieve** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_auth_methods_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_companies_list** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_companies_partial_update** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_companies_retrieve** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_companies_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_events_list** (13 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.created_after`: untyped_or_empty
  - `properties.query.properties.created_before`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.scope`: untyped_or_empty
  - `properties.query.properties.user`: untyped_or_empty
  - `properties.query.properties.user_id`: untyped_or_empty
- **api_v1_events_retention_retrieve** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_events_retrieve** (8 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.query.properties.scope`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_events_types_list** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_groups_create** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_groups_destroy** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_groups_list** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_groups_partial_update** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_groups_retrieve** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_groups_update** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_hosting_oauth_redirects_destroy** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_hosting_oauth_redirects_update** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_invitations_create** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_invitations_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_invitations_list** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_invitations_revoke** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_mcp_services_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_oauth_clients_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_oauth_clients_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_oauth_clients_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_oauth_clients_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_oauth_clients_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_oauth_provider_catalog_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.query.properties.include_legacy`: untyped_or_empty
- **api_v1_oauth_redirects_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_oauth_redirects_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_oauth_redirects_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_oauth_redirects_partial_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_oauth_redirects_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_oauth_social_apps_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_oauth_social_apps_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_oauth_social_apps_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_oauth_social_apps_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_personal_access_tokens_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_personal_access_tokens_list** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_personal_access_tokens_revoke** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.key_id`: missing_description
- **api_v1_scim_status** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_scim_tokens_create** (3 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_scim_tokens_list** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
- **api_v1_scim_tokens_revoke** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.token_id`: missing_description
- **api_v1_users_audience** (14 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.access`: untyped_or_empty
  - `properties.query.properties.count_only`: untyped_or_empty
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.query.properties.group_ids`: untyped_or_empty
  - `properties.query.properties.joined_after`: untyped_or_empty
  - `properties.query.properties.joined_before`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.roles`: untyped_or_empty
  - `properties.query.properties.seen_after`: untyped_or_empty
  - `properties.query.properties.seen_before`: untyped_or_empty
  - `properties.query.properties.user_ids`: untyped_or_empty
- **api_v1_users_destroy** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_users_list** (8 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.q`: untyped_or_empty
- **api_v1_users_retrieve** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_users_update** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.format`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description

### saas (0 issues)

### storage (222 issues)
- **api_v1_actions_deliveries_list** (11 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.action_rule_id`: untyped_or_empty
  - `properties.query.properties.company_id`: untyped_or_empty
  - `properties.query.properties.created_after`: untyped_or_empty
  - `properties.query.properties.created_before`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.scheduled_job_run_id`: untyped_or_empty
  - `properties.query.properties.status`: untyped_or_empty
- **api_v1_actions_deliveries_requeue** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_deliveries_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.delivery_id`: missing_description
- **api_v1_actions_event_log_list** (10 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.created_after`: untyped_or_empty
  - `properties.query.properties.created_before`: untyped_or_empty
  - `properties.query.properties.event_type`: untyped_or_empty
  - `properties.query.properties.page`: untyped_or_empty
  - `properties.query.properties.page_size`: untyped_or_empty
  - `properties.query.properties.scope`: untyped_or_empty
  - `properties.query.properties.user`: untyped_or_empty
  - `properties.query.properties.user_id`: untyped_or_empty
- **api_v1_actions_event_log_retention_retrieve** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **api_v1_actions_event_log_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.scope`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_event_log_types_list** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **api_v1_actions_events_list** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **api_v1_actions_rules_create** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **api_v1_actions_rules_destroy** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_list** (2 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
- **api_v1_actions_rules_partial_update** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_rotate_secret** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **api_v1_actions_rules_send_test** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.id`: missing_description
- **storage_v1_access_grant_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
- **storage_v1_access_grant_destroy** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.grant_id`: missing_description
- **storage_v1_access_grant_list** (8 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.bucket`: untyped_or_empty
  - `properties.query.properties.include_effective`: untyped_or_empty
  - `properties.query.properties.resource_id`: untyped_or_empty
  - `properties.query.properties.resource_type`: untyped_or_empty
- **storage_v1_bucket_empty_create** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_bucket_list** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
- **storage_v1_bucket_retrieve** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_object_authenticated_retrieve** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.download`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_object_copy_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
- **storage_v1_object_create** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_object_delete_many** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_object_destroy** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_object_id_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.object_id`: missing_description
- **storage_v1_object_info_authenticated_retrieve** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_object_list_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_object_move_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
- **storage_v1_object_prefix_create** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_object_prefix_destroy** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_object_prefix_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.query.properties.prefix`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_object_retrieve** (8 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.download`: untyped_or_empty
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_object_sign_create** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
- **storage_v1_object_sign_path_create** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_object_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_quota_company_update** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.company_id`: missing_description
- **storage_v1_quota_company_user_update** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.company_id`: missing_description
  - `properties.path_params.properties.user_id`: missing_description
- **storage_v1_quota_retrieve** (4 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
- **storage_v1_share_create** (7 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_share_link_destroy** (6 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.token`: missing_description
- **storage_v1_share_list** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.annotations`: missing_annotations
  - `properties.path_params`: missing_description
  - `properties.path_params.properties.bucket_id`: missing_description
  - `properties.path_params.properties.object_path`: missing_description
- **storage_v1_stats_retrieve** (5 issues)
  - `_tool.title`: missing_title
  - `_tool.description`: missing_description
  - `_tool.annotations`: missing_annotations
  - `_tool.description`: vague_tool_metadata
  - `properties.query.properties.days`: untyped_or_empty

## Remaining exceptions

None. All audited tools pass Inspector-aligned checks after normalization.
