#!/usr/bin/env python3
"""MCP device login (RFC 8628): discover, approve on identity, poll, call a tool.

Approval uses the same magic-link simulation as the authorization-code harness.
The script does not print access tokens, refresh tokens, device codes, or user codes.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import jwt
import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from headless_identity_oauth import complete_mcp_device_verification  # noqa: E402

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp').rstrip('/')
IDENTITY_ORIGIN = os.environ.get('IDENTITY_ORIGIN', 'http://localhost:8001').rstrip('/')
COMPOSE_FILE = os.environ.get('MCP_E2E_COMPOSE_FILE', '')
EMAIL = os.environ.get('MCP_E2E_USER_EMAIL', 'dev@localhost')
MCP_ACCEPT = 'application/json, text/event-stream'
DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'


def _company_id(mcp_url: str) -> int:
    parts = urlparse(mcp_url).path.strip('/').split('/')
    if len(parts) != 3 or parts[0] != 'c' or parts[2] != 'mcp':
        raise RuntimeError('MCP_URL must be {origin}/c/<company_id>/mcp')
    return int(parts[1])


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f'{parsed.scheme}://{parsed.netloc}'


def _challenge(company_id: int) -> str:
    metadata = f'{_origin(MCP_URL)}/.well-known/oauth-protected-resource/c/{company_id}/mcp'
    return f'Bearer realm="mcp", resource_metadata="{metadata}", scope="mcp"'


def _assert_metadata(company_id: int, issuer: str) -> None:
    origin = _origin(MCP_URL)
    paths = (
        f'/.well-known/oauth-protected-resource/c/{company_id}/mcp',
        f'/.well-known/oauth-protected-resource/c/{company_id}/mcp/',
        f'/c/{company_id}/mcp/.well-known/oauth-protected-resource',
    )
    for path in paths:
        response = requests.get(f'{origin}{path}', timeout=15)
        if response.status_code != 200:
            raise RuntimeError(f'{path} HTTP {response.status_code}')
        body = response.json()
        if body.get('authorization_servers') != [issuer]:
            raise RuntimeError(f'{path} authorization_servers {body.get("authorization_servers")!r} != issuer')
        if body.get('resource') != MCP_URL:
            raise RuntimeError(f'{path} resource {body.get("resource")!r}')
        if body.get('scopes_supported') != ['mcp']:
            raise RuntimeError(f'{path} scopes_supported {body.get("scopes_supported")!r}')
        if body.get('bearer_methods_supported') != ['header']:
            raise RuntimeError(f'{path} bearer_methods_supported {body.get("bearer_methods_supported")!r}')
        if 'device_authorization_endpoint' in body:
            raise RuntimeError(f'{path} must not publish device_authorization_endpoint')
    root = requests.get(f'{origin}/.well-known/oauth-protected-resource', timeout=15)
    if root.status_code != 404:
        raise RuntimeError(f'root protected-resource metadata HTTP {root.status_code}')
    unknown = requests.post(
        f'{origin}/c/0/mcp',
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}},
        timeout=15,
    )
    if unknown.status_code != 404 or 'WWW-Authenticate' in unknown.headers:
        raise RuntimeError('unknown company changed the existing 404 behavior')


def _poll_token(*, device_code: str, client_id: str, interval: int, expires_in: int) -> dict:
    deadline = time.time() + expires_in + 5
    wait = interval
    while time.time() < deadline:
        response = requests.post(
            f'{IDENTITY_ORIGIN}/oauth/token',
            data={
                'grant_type': DEVICE_GRANT,
                'device_code': device_code,
                'client_id': client_id,
                'resource': MCP_URL,
            },
            timeout=20,
        )
        if response.status_code == 200:
            body = response.json()
            if not body.get('access_token') or not body.get('refresh_token'):
                raise RuntimeError('token response missing access_token or refresh_token')
            return body
        try:
            error = response.json().get('error')
        except ValueError:
            error = ''
        if error == 'authorization_pending':
            time.sleep(wait)
            continue
        if error == 'slow_down':
            wait += 5
            time.sleep(wait)
            continue
        raise RuntimeError(f'token poll failed: HTTP {response.status_code} {error}')
    raise RuntimeError('device code expired before approval')


def _call_tool(access_token: str) -> None:
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': MCP_ACCEPT,
        'Content-Type': 'application/json',
    }
    init = requests.post(
        MCP_URL,
        json={
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'initialize',
            'params': {
                'protocolVersion': '2025-06-18',
                'capabilities': {},
                'clientInfo': {'name': 'e2e-device', 'version': '0'},
            },
        },
        headers=headers,
        timeout=20,
    )
    if init.status_code != 200:
        raise RuntimeError(f'initialize HTTP {init.status_code}')
    session = init.headers.get('Mcp-Session-Id')
    if session:
        headers['Mcp-Session-Id'] = session
        headers['MCP-Protocol-Version'] = '2025-06-18'
    call = requests.post(
        MCP_URL,
        json={
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'tools/call',
            'params': {'name': 'ai_list_services', 'arguments': {}},
        },
        headers=headers,
        timeout=20,
    )
    if call.status_code != 200:
        raise RuntimeError(f'tools/call HTTP {call.status_code}')
    body = call.json()
    if 'error' in body or (body.get('result') or {}).get('isError'):
        raise RuntimeError('tools/call failed')


def main() -> int:
    if not COMPOSE_FILE:
        raise RuntimeError('MCP_E2E_COMPOSE_FILE is required')
    company_id = _company_id(MCP_URL)
    unauth = requests.post(
        MCP_URL,
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}},
        headers={'Accept': MCP_ACCEPT, 'Content-Type': 'application/json'},
        timeout=15,
    )
    if unauth.status_code != 401 or unauth.headers.get('WWW-Authenticate') != _challenge(company_id):
        raise RuntimeError(f'unexpected 401 challenge: HTTP {unauth.status_code}')
    probed = requests.get(MCP_URL, timeout=15)
    if probed.status_code != 401 or probed.headers.get('WWW-Authenticate') != _challenge(company_id):
        raise RuntimeError(f'GET without a token did not challenge: HTTP {probed.status_code}')

    as_meta = requests.get(f'{IDENTITY_ORIGIN}/.well-known/oauth-authorization-server', timeout=15)
    as_meta.raise_for_status()
    metadata = as_meta.json()
    issuer = str(metadata.get('issuer') or '')
    if not issuer:
        raise RuntimeError('identity authorization server metadata has no issuer')
    _assert_metadata(company_id, issuer)
    device_endpoint = str(metadata.get('device_authorization_endpoint') or '')
    grants = metadata.get('grant_types_supported') or []
    if not device_endpoint or DEVICE_GRANT not in grants:
        print(
            '[device] skipped token round-trip: identity metadata does not advertise '
            'device authorization (identity-service device-login). Discovery checks passed.',
            file=sys.stderr,
        )
        return 0

    reg = requests.post(
        f'{IDENTITY_ORIGIN}/oauth/mcp/register',
        json={'redirect_uris': ['http://127.0.0.1/callback'], 'client_name': 'e2e-device'},
        timeout=20,
    )
    if reg.status_code not in (200, 201):
        raise RuntimeError(f'client registration HTTP {reg.status_code}')
    client_id = reg.json()['client_id']
    started = requests.post(
        device_endpoint,
        data={'client_id': client_id, 'resource': MCP_URL},
        timeout=20,
    )
    if started.status_code != 200:
        raise RuntimeError(f'device authorization HTTP {started.status_code}')
    device = started.json()
    for key in ('device_code', 'user_code', 'verification_uri_complete', 'interval', 'expires_in'):
        if key not in device:
            raise RuntimeError(f'device authorization response missing {key}')

    complete_mcp_device_verification(
        device['verification_uri_complete'],
        user_code=device['user_code'],
        identity_origin=IDENTITY_ORIGIN,
        email=EMAIL,
        company_id=company_id,
        compose_file=COMPOSE_FILE,
    )
    token = _poll_token(
        device_code=device['device_code'],
        client_id=client_id,
        interval=int(device['interval']),
        expires_in=int(device['expires_in']),
    )
    claims = jwt.decode(token['access_token'], options={'verify_signature': False})
    aud = claims.get('aud')
    if isinstance(aud, list):
        aud = aud[0] if aud else ''
    if aud != MCP_URL:
        raise RuntimeError('access token aud is not the company MCP URL')
    sub = str(claims.get('sub') or '')
    agent_id = str(claims.get('agent_id') or '')
    if not sub.startswith('agent:') or sub != f'agent:{agent_id}' or not agent_id:
        raise RuntimeError('access token sub/agent_id is not an agent principal')
    if int(claims.get('company_id')) != company_id:
        raise RuntimeError('access token company_id does not match the MCP URL')
    for key in ('mcp_access', 'mcp_read', 'mcp_destructive', 'scope', 'grant_version'):
        if key not in claims:
            raise RuntimeError(f'access token missing {key}')
    if not isinstance(claims.get('mcp_destructive'), bool):
        raise RuntimeError('mcp_destructive is not a boolean')
    if 'ai' not in str(claims.get('scope') or '').split():
        raise RuntimeError('access token scope does not include ai')
    _call_tool(token['access_token'])
    print('[device] discovery, approval, poll, tools/call: ok')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'[device] {exc}', file=sys.stderr)
        raise SystemExit(1) from exc
