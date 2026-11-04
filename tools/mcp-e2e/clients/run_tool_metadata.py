#!/usr/bin/env python3
"""Assert live gateway tools/list exports titles, descriptions, annotations, and names."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apps.connector.mcp_tool_metadata_checks import validate_tools_list  # noqa: E402

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
MCP_ACCEPT = 'application/json, text/event-stream'
TOKEN_FILE = os.environ.get('MCP_E2E_TOKEN_FILE', '')


def main() -> int:
    if not TOKEN_FILE or not Path(TOKEN_FILE).is_file():
        print('[tool-metadata] skipped (no OAuth token file)', file=sys.stderr)
        return 0
    token = Path(TOKEN_FILE).read_text(encoding='utf-8').strip()
    response = requests.post(
        MCP_URL,
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}},
        headers={'Authorization': f'Bearer {token}', 'Accept': MCP_ACCEPT},
        timeout=30,
    )
    if response.status_code != 200:
        print(f'[tool-metadata] tools/list HTTP {response.status_code}', file=sys.stderr)
        return 1
    tools = (response.json().get('result') or {}).get('tools') or []
    if not tools:
        print('[tool-metadata] no tools exported', file=sys.stderr)
        return 1
    errors = validate_tools_list([t for t in tools if isinstance(t, dict)])
    if errors:
        print('[tool-metadata] failures:', file=sys.stderr)
        for line in errors[:30]:
            print(f'  - {line}', file=sys.stderr)
        return 1
    sample = next((t for t in tools if t.get('name') == 'ai_list_services'), tools[0])
    print(
        f'[tool-metadata] {len(tools)} tool(s): names, titles, descriptions, annotations ok; '
        f'sample {sample.get("name")!r} title={sample.get("title")!r}'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
