#!/usr/bin/env python3
"""Fail when any MCP tool inputSchema is untyped or violates strict client subsets."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

import django  # noqa: E402

django.setup()

from drf_spectacular.generators import SchemaGenerator  # noqa: E402

from apps.connector.mcp_openapi_tools import tools_from_schema  # noqa: E402
from apps.connector.mcp_tool_schema import audit_tool_input_schemas, normalize_mcp_tool  # noqa: E402

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
MCP_ACCEPT = 'application/json, text/event-stream'
TOKEN_FILE = os.environ.get('MCP_E2E_TOKEN_FILE', '')


def _local_tools() -> list[dict]:
    schema = SchemaGenerator().get_schema(request=None, public=True)
    return tools_from_schema(schema)


def _live_tools(token: str) -> list[dict]:
    response = requests.post(
        MCP_URL,
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}},
        headers={'Authorization': f'Bearer {token}', 'Accept': MCP_ACCEPT},
        timeout=30,
    )
    if response.status_code != 200:
        raise RuntimeError(f'tools/list failed: HTTP {response.status_code} {response.text[:300]}')
    payload = response.json()
    result = payload.get('result') or {}
    tools = result.get('tools') or []
    return [normalize_mcp_tool(t) for t in tools if isinstance(t, dict)]


def main() -> int:
    tools = _local_tools()
    if TOKEN_FILE and Path(TOKEN_FILE).is_file():
        token = Path(TOKEN_FILE).read_text(encoding='utf-8').strip()
        if token:
            tools = _live_tools(token)
    issues = audit_tool_input_schemas(tools)
    if issues:
        print('[schema-audit] MCP tool inputSchema violations:', file=sys.stderr)
        for name, path, reason in issues:
            print(f'  - {name} {path}: {reason}', file=sys.stderr)
        return 1
    print(f'[schema-audit] {len(tools)} tool(s) passed strict inputSchema audit')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
