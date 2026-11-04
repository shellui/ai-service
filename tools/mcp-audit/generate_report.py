#!/usr/bin/env python3
"""Generate docs/mcp-tool-schema-audit.md from OpenAPI across Shellui MCP services."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = ROOT / 'docs' / 'mcp-tool-schema-audit.md'
EXPORT_SNIPPET = """
import json, os, sys
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()
from drf_spectacular.generators import SchemaGenerator
json.dump(SchemaGenerator().get_schema(request=None, public=True), sys.stdout)
"""
ARTIFACT_PATH = ROOT / 'docs' / 'mcp-tool-schema-audit.json'

SERVICES: list[tuple[str, Path]] = [
    ('ai', ROOT),
    ('identity', ROOT / '.e2e-identity'),
    ('storage', ROOT / '.e2e-storage-service'),
    ('hosting', ROOT / '.e2e-hosting-service'),
    ('email', ROOT / '.e2e-email-service'),
    ('saas', ROOT / '.e2e-saas-service'),
]


def _service_env(repo: Path) -> dict[str, str]:
    env = {
        **os.environ,
        'SECRET_KEY': 'mcp-audit-not-for-production-0123456789abcdef0123456789ab',
        'DEBUG': 'true',
        'JWT_HS256_FALLBACK_SECRET': 'mcp-audit-not-for-production-0123456789abcdef0123456789ab',
        'POSTGRES_DATABASE_URL': f'sqlite:///{repo / ".mcp-audit.sqlite3"}',
        'REDIS_URL': 'redis://127.0.0.1:6379/0',
        'IDENTITY_ISSUER': 'http://localhost:8001',
        'IDENTITY_JWKS_URL': 'http://localhost:8001/.well-known/jwks.json',
        'DJANGO_SETTINGS_MODULE': 'config.settings',
    }
    env.pop('VIRTUAL_ENV', None)
    return env


def _export_schema(service: str, repo: Path) -> dict:
    if not repo.is_dir():
        raise FileNotFoundError(f'missing checkout: {repo}')
    env = _service_env(repo)
    subprocess.run(['uv', 'sync', '-q'], cwd=repo, check=False, env=env)
    proc = subprocess.run(
        ['uv', 'run', 'python', '-c', EXPORT_SNIPPET],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f'{service} OpenAPI export failed:\n{proc.stderr}\n{proc.stdout[-2000:]}')
    return json.loads(proc.stdout)


def _audit_service(service: str, schema: dict) -> dict:
    from apps.connector.mcp_openapi_tools import tools_from_schema
    from apps.connector.mcp_schema_inspector import inspect_tools, legacy_tools_from_schema, summarize_issues
    from apps.connector.mcp_tool_schema import normalize_mcp_tool
    from apps.connector.mcp_tool_naming import gateway_export_name

    legacy = legacy_tools_from_schema(schema)
    typed = tools_from_schema(schema)
    taken: set[str] = set()
    name_mappings: list[dict[str, str]] = []
    after_gateway: list[dict] = []
    for tool in typed:
        meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
        legacy_name = str(meta.get('legacy_tool_name') or tool.get('name') or '')
        service_name = str(tool.get('name') or '')
        if service == 'ai':
            gateway_name = service_name
            taken.add(gateway_name)
        else:
            gateway_name = gateway_export_name(service, service_name, taken=taken)
        name_mappings.append(
            {
                'service': service,
                'legacy_name': legacy_name,
                'service_tool_name': service_name,
                'gateway_tool_name': gateway_name,
            }
        )
        after_gateway.append(normalize_mcp_tool({**tool, 'name': gateway_name}, schema))
    before_issues = inspect_tools(service, legacy)
    after_source_issues = inspect_tools(service, typed)
    after_gateway_issues = inspect_tools(service, after_gateway)
    return {
        'service': service,
        'tool_count': len(typed),
        'name_mappings': name_mappings,
        'before': [i.__dict__ for i in before_issues],
        'after_source': [i.__dict__ for i in after_source_issues],
        'after_gateway': [i.__dict__ for i in after_gateway_issues],
        'before_summary': summarize_issues(before_issues),
        'after_source_summary': summarize_issues(after_source_issues),
        'after_gateway_summary': summarize_issues(after_gateway_issues),
    }


def main() -> int:
    sys.path.insert(0, str(ROOT))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    for key, value in _service_env(ROOT).items():
        if key in {'SECRET_KEY', 'DEBUG', 'JWT_HS256_FALLBACK_SECRET', 'POSTGRES_DATABASE_URL', 'REDIS_URL', 'IDENTITY_ISSUER', 'IDENTITY_JWKS_URL', 'DJANGO_SETTINGS_MODULE'}:
            os.environ.setdefault(key, value)

    import django

    django.setup()

    from apps.connector.mcp_schema_inspector import SchemaIssue, format_report_markdown

    payloads: list[dict] = []
    for service, path in SERVICES:
        if service != 'ai' and not path.is_dir():
            payloads.append({'service': service, 'tool_count': 0, 'error': f'missing checkout: {path}', 'name_mappings': []})
            continue
        try:
            schema = _export_schema(service, path)
            payloads.append(_audit_service(service, schema))
        except (FileNotFoundError, RuntimeError) as exc:
            payloads.append({'service': service, 'tool_count': 0, 'error': str(exc), 'name_mappings': []})

    services_meta: dict[str, dict] = {}
    before: dict[str, list[SchemaIssue]] = {}
    after: dict[str, list[SchemaIssue]] = {}
    for row in payloads:
        svc = row['service']
        services_meta[svc] = {'tool_count': row.get('tool_count', 0)}
        if row.get('error'):
            services_meta[svc]['note'] = row['error']
            continue
        before[svc] = [SchemaIssue(**item) for item in row['before']]
        after[svc] = [SchemaIssue(**item) for item in row['after_gateway']]

    name_mappings = [row for payload in payloads for row in payload.get('name_mappings', [])]
    markdown = format_report_markdown(
        services=services_meta,
        before=before,
        after=after,
        name_mappings=name_mappings,
    )
    DOC_PATH.write_text(markdown, encoding='utf-8')
    ARTIFACT_PATH.write_text(json.dumps(payloads, indent=2), encoding='utf-8')
    print(f'Wrote {DOC_PATH} and {ARTIFACT_PATH}')
    remaining = sum(len(v) for v in after.values())
    if remaining:
        print(f'ERROR: {remaining} issues remain after gateway normalization', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
