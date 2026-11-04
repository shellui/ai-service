#!/usr/bin/env python3
"""Fail when any MCP tool inputSchema is untyped or violates strict client subsets."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
MCP_ACCEPT = 'application/json, text/event-stream'
TOKEN_FILE = os.environ.get('MCP_E2E_TOKEN_FILE', '')


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
    return [t for t in tools if isinstance(t, dict)]


def _audit(tools: list[dict]) -> list[tuple[str, str, str]]:
    root = Path(__file__).resolve().parents[3]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from apps.connector.mcp_schema_inspector import inspect_tools, summarize_issues
    from apps.connector.mcp_tool_schema import normalize_mcp_tool

    normalized = [normalize_mcp_tool(t) for t in tools]
    issues = inspect_tools('live', normalized)
    summary = summarize_issues(issues)
    if summary['total_issues']:
        return [(i.tool, i.path, i.category) for i in issues]
    return []


def main() -> int:
    token = ''
    if TOKEN_FILE and Path(TOKEN_FILE).is_file():
        token = Path(TOKEN_FILE).read_text(encoding='utf-8').strip()
    if not token:
        print('[schema-audit] skipped (no OAuth token file)', file=sys.stderr)
        return 0
    tools = _live_tools(token)
    issues = _audit(tools)
    if issues:
        print('[schema-audit] MCP tool inputSchema violations:', file=sys.stderr)
        for name, path, category in issues:
            print(f'  - {name} {path}: {category}', file=sys.stderr)
        return 1
    print(f'[schema-audit] {len(tools)} live tool(s) passed strict inputSchema audit')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
