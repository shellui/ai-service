#!/usr/bin/env python3
"""Negative MCP / OAuth checks (HTTP; not a substitute for SDK happy paths)."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from urllib.parse import urlencode

import jwt
import requests

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
MCP_URL_C2 = os.environ.get('MCP_URL_COMPANY_2', 'http://localhost:8006/c/2/mcp')
PLAIN_MCP = os.environ.get('PLAIN_MCP_URL', 'http://localhost:8006/mcp')
IDENTITY_ORIGIN = os.environ.get('IDENTITY_ORIGIN', 'http://127.0.0.1:8001').rstrip('/')
ISSUER = IDENTITY_ORIGIN
AUD = MCP_URL
SECRET = os.environ['E2E_IDENTITY_SECRET_KEY']
MCP_ACCEPT = 'application/json, text/event-stream'
COMPOSE_FILE = os.environ.get('MCP_E2E_COMPOSE_FILE', '')


def _rpc(method: str, **params):
    return {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}


def _agent_token(**overrides):
    now = int(time.time())
    claims = {
        'token_type': 'access',
        'sub': 'agent:neg-test',
        'agent_id': 'neg-test',
        'company_id': 1,
        'scope': 'ai identity',
        'mcp_access': 'full',
        'mcp_read': 'safe',
        'aud': AUD,
        'iss': ISSUER,
        'iat': now,
        'exp': now + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, SECRET, algorithm='HS256')


def check(name: str, ok: bool, detail: str = '') -> None:
    if not ok:
        raise AssertionError(f'{name} failed: {detail}')
    print(f'[negatives] {name}: ok')


def main() -> int:
    token_c1 = _agent_token()
    # Wrong company URL
    r = requests.post(
        MCP_URL_C2,
        json=_rpc('tools/list'),
        headers={'Authorization': f'Bearer {token_c1}', 'Accept': MCP_ACCEPT},
        timeout=15,
    )
    check('company 1 token rejected on /c/2/mcp', r.status_code == 401)

    expired = _agent_token(exp=int(time.time()) - 60)
    r = requests.post(
        MCP_URL,
        json=_rpc('tools/list'),
        headers={'Authorization': f'Bearer {expired}', 'Accept': MCP_ACCEPT},
        timeout=15,
    )
    check('expired token rejected', r.status_code == 401)

    r = requests.post(PLAIN_MCP, json=_rpc('tools/list'), headers={'Accept': MCP_ACCEPT}, timeout=15)
    check('plain /mcp company_required', r.status_code == 404 and r.json().get('error') == 'company_required')

    # OAuth: wrong redirect_uri
    reg = requests.post(
        f'{IDENTITY_ORIGIN}/oauth/mcp/register',
        json={'redirect_uris': ['http://127.0.0.1:8765/callback'], 'client_name': 'e2e-neg'},
        timeout=15,
    )
    check('dynamic registration', reg.status_code == 201, reg.text)
    client_id = reg.json()['client_id']
    q = urlencode(
        {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': 'http://evil.test/cb',
            'code_challenge': 'x' * 43,
            'code_challenge_method': 'S256',
            'resource': MCP_URL,
        }
    )
    r = requests.get(f'{IDENTITY_ORIGIN}/oauth/mcp/authorize?{q}', timeout=15, allow_redirects=False)
    check('wrong redirect_uri rejected', r.status_code == 400, r.text[:200])

    q_no_pkce = urlencode(
        {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': 'http://127.0.0.1:8765/callback',
            'resource': MCP_URL,
        }
    )
    r = requests.get(f'{IDENTITY_ORIGIN}/oauth/mcp/authorize?{q_no_pkce}', timeout=15, allow_redirects=False)
    check('missing PKCE rejected', r.status_code == 400, r.text[:200])

    # Staff user refused at authorize (identity oauth_views; in-container Django client)
    if not COMPOSE_FILE:
        check('staff MCP OAuth refused', False, 'MCP_E2E_COMPOSE_FILE not set')
    staff_script = f"""
import base64
import hashlib
from django.contrib.auth import get_user_model
from django.test import Client
from urllib.parse import urlencode
verifier = 'y' * 43
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
User = get_user_model()
client = Client(HTTP_HOST='localhost')
client.force_login(User.objects.get(username='admin'))
q = urlencode(
    {{
        'response_type': 'code',
        'client_id': {client_id!r},
        'redirect_uri': 'http://127.0.0.1:8765/callback',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'resource': {MCP_URL!r},
    }}
)
response = client.get('/oauth/mcp/authorize?' + q)
if response.status_code != 403:
    raise SystemExit(response.status_code)
body = response.content.decode(errors='replace')
if 'staff_refused' not in body and "Staff accounts can't connect MCP clients" not in body:
    raise SystemExit('missing staff_refused copy')
"""
    proc = subprocess.run(
        ['docker', 'compose', '-f', COMPOSE_FILE, 'exec', '-T', 'identity', 'python', 'manage.py', 'shell', '-c', staff_script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    check(
        'staff MCP OAuth refused',
        proc.returncode == 0,
        (proc.stderr or proc.stdout or f'exit {proc.returncode}').strip()[:300],
    )

    print('[negatives] all checks passed')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'[negatives] {exc}', file=sys.stderr)
        raise
