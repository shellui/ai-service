#!/usr/bin/env python3
"""Minimal SaaS MCP stub for e2e (empty tools/list)."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length) if length else b'{}'
        try:
            payload = json.loads(raw.decode('utf-8') or '{}')
        except ValueError:
            payload = {}
        method = payload.get('method')
        req_id = payload.get('id')
        if method == 'tools/list':
            body = {'jsonrpc': '2.0', 'id': req_id, 'result': {'tools': []}}
        else:
            body = {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32601, 'message': 'Not found'}}
        data = json.dumps(body).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
