#!/usr/bin/env python3
"""Assert identity ``POST /oauth/mcp/token`` accepts application/x-www-form-urlencoded (RFC 6749)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode

import requests

ROOT = Path(__file__).resolve().parents[1]
HEADLESS = ROOT / 'headless_identity_oauth.py'

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
IDENTITY_ORIGIN = os.environ.get('IDENTITY_ORIGIN', 'http://127.0.0.1:8001').rstrip('/')
COMPOSE_FILE = os.environ['MCP_E2E_COMPOSE_FILE']
REDIRECT = os.environ.get('MCP_E2E_CALLBACK_URL', 'http://127.0.0.1:8767/callback')


def main() -> int:
    reg = requests.post(
        f'{IDENTITY_ORIGIN}/oauth/mcp/register',
        json={'redirect_uris': [REDIRECT], 'client_name': 'e2e-form-body'},
        timeout=20,
    )
    reg.raise_for_status()
    client_id = reg.json()['client_id']
    verifier = 'f' * 43
    import hashlib, base64

    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip('=')
    auth_url = (
        f'{IDENTITY_ORIGIN}/oauth/mcp/authorize?'
        + urlencode(
            {
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': REDIRECT,
                'code_challenge': challenge,
                'code_challenge_method': 'S256',
                'resource': MCP_URL,
                'state': 'form',
            }
        )
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(HEADLESS),
            '--authorization-url',
            auth_url,
            '--identity-origin',
            IDENTITY_ORIGIN,
            '--compose-file',
            COMPOSE_FILE,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    code = proc.stdout.strip().splitlines()[0]
    token = requests.post(
        f'{IDENTITY_ORIGIN}/oauth/mcp/token',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT,
            'client_id': client_id,
            'code_verifier': verifier,
            'resource': MCP_URL,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=20,
    )
    if token.status_code != 200:
        raise RuntimeError(f'token exchange failed: {token.status_code} {token.text}')
    body = token.json()
    refresh = body.get('refresh_token')
    if not refresh:
        raise RuntimeError('missing refresh_token')
    refreshed = requests.post(
        f'{IDENTITY_ORIGIN}/oauth/mcp/token',
        data={'grant_type': 'refresh_token', 'refresh_token': refresh, 'resource': MCP_URL},
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=20,
    )
    if refreshed.status_code != 200:
        raise RuntimeError(f'refresh failed: {refreshed.status_code} {refreshed.text}')
    print('[oauth-form] authorization_code + refresh_token (form-urlencoded): ok')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
