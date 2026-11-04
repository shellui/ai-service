#!/usr/bin/env python3
"""Assert live gateway tools/list exports titles and MCP annotations."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
MCP_ACCEPT = 'application/json, text/event-stream'
TOKEN_FILE = os.environ.get('MCP_E2E_TOKEN_FILE', '')
ANNOTATION_KEYS = ('readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint')


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
    errors: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get('name') or '')
        if 'api_v1' in name or '__' in name:
            errors.append(f'{name}: invalid tool name (api_v1 or double underscore)')
        title = str(tool.get('title') or '').strip()
        if len(title) < 3:
            errors.append(f'{name}: missing title')
        desc = str(tool.get('description') or '').strip()
        if len(desc) < 20:
            errors.append(f'{name}: description too short')
        ann = tool.get('annotations')
        if not isinstance(ann, dict):
            errors.append(f'{name}: missing annotations')
            continue
        for key in ANNOTATION_KEYS:
            if key not in ann:
                errors.append(f'{name}: annotations.{key} missing')
    if errors:
        print('[tool-metadata] failures:', file=sys.stderr)
        for line in errors[:20]:
            print(f'  - {line}', file=sys.stderr)
        return 1
    sample = next((t for t in tools if t.get('name') == 'ai_list_services'), tools[0])
    print(
        f'[tool-metadata] {len(tools)} tool(s): titles + annotations ok; '
        f'sample {sample.get("name")!r} title={sample.get("title")!r}'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
