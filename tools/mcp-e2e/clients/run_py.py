#!/usr/bin/env python3
"""MCP conformance: official Python MCP SDK + Streamable HTTP + Shellui OAuth."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import anyio
from mcp.client.auth import OAuthClientProvider
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientMetadata, OAuthToken

ROOT = Path(__file__).resolve().parents[1]
HEADLESS = ROOT / 'headless_identity_oauth.py'

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
CALLBACK_URL = os.environ.get('MCP_E2E_CALLBACK_URL', 'http://127.0.0.1:8766/callback')
COMPOSE_FILE = os.environ.get('MCP_E2E_COMPOSE_FILE', '')
IDENTITY_ORIGIN = os.environ.get('IDENTITY_ORIGIN', 'http://localhost:8001')


class _MemoryStorage:
    def __init__(self) -> None:
        self._tokens: OAuthToken | None = None
        self._client_info = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self):
        return self._client_info

    async def set_client_info(self, client_info) -> None:
        self._client_info = client_info


def _run_headless(auth_url: str) -> str:
    if not COMPOSE_FILE:
        raise RuntimeError('MCP_E2E_COMPOSE_FILE is required')
    py = os.environ.get('MCP_E2E_PYTHON', sys.executable)
    proc = subprocess.run(
        [
            py,
            str(HEADLESS),
            '--authorization-url',
            auth_url,
            '--identity-origin',
            IDENTITY_ORIGIN,
            '--compose-file',
            COMPOSE_FILE,
            '--email',
            os.environ.get('MCP_E2E_USER_EMAIL', 'dev@localhost'),
            '--company-id',
            os.environ.get('MCP_E2E_COMPANY_ID', '1'),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or 'headless OAuth failed')
    return proc.stdout.strip().splitlines()[0]


async def main() -> None:
    storage = _MemoryStorage()
    holder: dict[str, str | None] = {'code': None, 'state': None}

    async def redirect_handler(url: str) -> None:
        code = await asyncio.to_thread(_run_headless, url)
        holder['code'] = code

    async def callback_handler() -> AuthorizationCodeResult:
        while holder['code'] is None:
            await asyncio.sleep(0.05)
        return AuthorizationCodeResult(code=holder['code'], state=holder.get('state'))

    metadata = OAuthClientMetadata(
        client_name='Shellui MCP E2E (Python SDK)',
        redirect_uris=[CALLBACK_URL],
        grant_types=['authorization_code', 'refresh_token'],
        response_types=['code'],
        token_endpoint_auth_method='none',
    )
    auth = OAuthClientProvider(
        MCP_URL,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
    async with create_mcp_http_client(auth=auth) as http_client:
        async with streamable_http_client(MCP_URL, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = {t.name for t in tools.tools}
                if 'api_v1_mcp_services_list' not in names:
                    raise RuntimeError(f'api_v1_mcp_services_list missing; got {sorted(names)}')
                result = await session.call_tool('api_v1_mcp_services_list', {})
                if result.isError:
                    raise RuntimeError(f'tools/call failed: {result}')
                tokens = await storage.get_tokens()
                if not tokens or not tokens.refresh_token:
                    raise RuntimeError('no refresh_token after OAuth')
    print('[py-sdk] initialize, tools/list, tools/call, refresh_token: ok')


if __name__ == '__main__':
    anyio.run(main)
