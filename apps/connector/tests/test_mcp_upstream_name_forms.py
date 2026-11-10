"""Gateway names stay stable across the in-flight service renames.

- hosting-service PR #81 (``f9135809``) keeps ``operationId`` and sets
  ``x-mcp.tool_name`` to the local verb_noun (``list_apps``). ``tools/list``
  publishes ``hosting_list_apps``.
- storage-service PR #64 (``ff18fc77``) keeps ``operationId`` and sets
  ``x-mcp.tool_name`` to the full gateway name (``storage_list_bucket``).
  ``tools/list`` publishes that same string.
- identity-service PR #147 (``8a034af``) renames ``operationId`` itself to
  ``identity_<verb>_<noun>`` (``identity_create_groups``). shellui-django then
  lists that operation id as the tool name.
- email-service PR #51 (``fcbc04fb``) keeps ``operationId`` as ``api_v1_*`` and
  sets ``x-mcp.tool_name`` to the full gateway name (``email_create_newsletters``).

Refreshing those OpenAPI documents must keep the pinned 224 names and the same
destructive and approval flags. ``identity_revoke_personal_access_tokens`` and
``identity_revoke_scim_tokens`` stay destructive in every spelling.
"""

from __future__ import annotations

import json
from pathlib import Path

from django.test import SimpleTestCase
from shellui_django.mcp.openapi_mcp import tool_access_flags
from shellui_django.mcp.openapi_tools import tools_from_schema as shellui_tools_from_schema
from shellui_django.mcp.write_gate import decide_write

from apps.connector.mcp_approval_gate import tool_traits_from_export
from apps.connector.mcp_tool_naming import resolve_mcp_tool_name, select_newest_api_version_operations
from apps.connector.mcp_tool_schema import normalize_mcp_tool
from apps.connector.mcp_views import iter_gateway_remote_exports

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
SNAPSHOT_PATH = FIXTURES / 'mcp_tool_release_snapshot.json'
# hosting-service PR #81 f9135809de5bf5cc2d5d8a633d6ca77530417ffb
# storage-service PR #64 ff18fc770776540b4a8bc2136ea93fb0ce96d0da
# identity-service PR #147 8a034af82f324d63348dc875a0bb6f53c70e02ee
# email-service PR #51 fcbc04fba15a37d935289c13e949c47352a1b513
SERVICE_FIXTURES = {
    'hosting': FIXTURES / 'openapi' / 'hosting-pr81.json',
    'storage': FIXTURES / 'openapi' / 'storage-pr64.json',
    'identity': FIXTURES / 'openapi' / 'identity-pr147.json',
    'email': FIXTURES / 'openapi' / 'email-pr51.json',
}
IDENTITY_REVOKE_TOOLS = (
    'identity_revoke_personal_access_tokens',
    'identity_revoke_scim_tokens',
)
# Identity's operation ids are already the gateway names, so the shellui tool
# name is the prefixed form. Hosting and storage still emit operationId slugs
# until their rename helper runs.
STYLES = {
    'hosting': ('legacy', 'local', 'prefixed', 'legacy_with_x_mcp'),
    'storage': ('legacy', 'local', 'prefixed', 'legacy_with_x_mcp'),
    'identity': ('operation_id', 'local', 'prefixed'),
    'email': ('legacy', 'local', 'prefixed', 'legacy_with_x_mcp'),
}


def _tool_names_by_operation(schema: dict) -> dict[str, str]:
    names: dict[str, str] = {}
    for _path, _method, operation in select_newest_api_version_operations(schema):
        x_mcp = operation.get('x-mcp') if isinstance(operation.get('x-mcp'), dict) else {}
        tool_name = str(x_mcp.get('tool_name') or '').strip()
        if tool_name:
            names[str(operation.get('operationId') or '')] = tool_name
    return names


def _wire_tools(schema: dict, service: str, style: str) -> list[dict]:
    declared = _tool_names_by_operation(schema)
    tools: list[dict] = []
    for tool in shellui_tools_from_schema(schema):
        meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
        operation_id = str(meta.get('operationId') or '')
        explicit = declared.get(operation_id, '')
        prefix = f'{service}_'
        local = explicit[len(prefix) :] if explicit.startswith(prefix) else explicit
        if style == 'legacy':
            public = {k: v for k, v in tool.items() if not str(k).startswith('_')}
        elif style == 'operation_id':
            # shellui names the tool from operationId. Identity's ids are already
            # ``identity_<verb>_<noun>``.
            public = {k: v for k, v in tool.items() if not str(k).startswith('_')}
        elif style == 'local':
            public = {k: v for k, v in tool.items() if not str(k).startswith('_')}
            public['name'] = local or str(operation_id)[len(prefix) :]
        elif style == 'prefixed':
            public = {k: v for k, v in tool.items() if not str(k).startswith('_')}
            if explicit.startswith(prefix):
                public['name'] = explicit
            elif local:
                public['name'] = f'{prefix}{local}'
            else:
                public['name'] = str(operation_id)
        elif style == 'legacy_with_x_mcp':
            copied = json.loads(json.dumps(tool))
            x_mcp = dict(copied.get('_meta', {}).get('x-mcp') or {})
            if explicit:
                x_mcp['tool_name'] = explicit
            copied.setdefault('_meta', {})['x-mcp'] = x_mcp
            public = copied
        else:
            raise AssertionError(style)
        tools.append(public)
    return tools


class UpstreamNameFormTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding='utf-8'))
        cls.snapshot = {row['name']: row for row in snapshot}

    def test_service_rename_prs_keep_gateway_names_and_flags(self):
        for service, path in SERVICE_FIXTURES.items():
            schema = json.loads(path.read_text(encoding='utf-8'))
            expected = {name: row for name, row in self.snapshot.items() if name.startswith(f'{service}_')}
            self.assertTrue(expected, service)
            for style in STYLES[service]:
                with self.subTest(service=service, style=style):
                    exports = iter_gateway_remote_exports(
                        [normalize_mcp_tool(tool) for tool in _wire_tools(schema, service, style)],
                        service_id=service,
                    )
                    got = {}
                    for export_name, exported, route in exports:
                        self.assertFalse(
                            export_name.startswith(f'{service}_{service}_'),
                            export_name,
                        )
                        meta = exported.get('_meta') if isinstance(exported.get('_meta'), dict) else {}
                        read_only, destructive = tool_traits_from_export(
                            exported,
                            method=str(meta.get('method') or 'GET'),
                        )
                        got[export_name] = (read_only, destructive, route['downstream_name'])
                    self.assertEqual(set(got), set(expected), style)
                    for name, row in expected.items():
                        read_only, destructive, _downstream = got[name]
                        self.assertEqual(read_only, row['read_only'], name)
                        self.assertEqual(destructive, row['destructive'], name)
                        self.assertEqual(
                            (not read_only),
                            row['needs_approval'],
                            name,
                        )
                    if service == 'identity':
                        for name in IDENTITY_REVOKE_TOOLS:
                            read_only, destructive, _downstream = got[name]
                            self.assertFalse(read_only, style)
                            self.assertTrue(destructive, style)

    def test_refreshed_branch_fixtures_keep_snapshot_names_and_flags(self):
        """OpenAPI from each rename branch, named by resolve_mcp_tool_name, matches the snapshot."""
        flags: dict[str, dict] = {}
        for service, path in SERVICE_FIXTURES.items():
            schema = json.loads(path.read_text(encoding='utf-8'))
            for route, method, operation in select_newest_api_version_operations(schema):
                local = resolve_mcp_tool_name(operation, method, route)
                export = f'{service}_{local}'
                self.assertFalse(export.startswith(f'{service}_{service}_'), export)
                self.assertNotIn(export, flags, export)
                access = tool_access_flags(operation)
                decision = decide_write(
                    method=method.upper(),
                    access_mode='ask',
                    destructive=bool(access['destructive']),
                    allow_destructive_without_asking=False,
                    tool_read_only=bool(access['read_only']),
                )
                flags[export] = {
                    'read_only': bool(access['read_only']),
                    'destructive': bool(access['destructive']),
                    'needs_approval': bool(decision.needs_approval),
                }
        self.assertEqual(set(flags) | {'ai_list_services'}, set(self.snapshot))
        self.assertEqual(len(self.snapshot), 224)
        for name, row in self.snapshot.items():
            if name == 'ai_list_services':
                continue
            got = flags[name]
            self.assertEqual(got['read_only'], row['read_only'], name)
            self.assertEqual(got['destructive'], row['destructive'], name)
            self.assertEqual(got['needs_approval'], row['needs_approval'], name)
        for name in IDENTITY_REVOKE_TOOLS:
            self.assertTrue(flags[name]['destructive'], name)
            self.assertFalse(flags[name]['read_only'], name)
            self.assertTrue(flags[name]['needs_approval'], name)
