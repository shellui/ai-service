#!/usr/bin/env python3
"""E2e checks for SaaS OAuth opt-in metadata and personal agent bearer tokens."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests

CLIENTS = Path(__file__).resolve().parent
if str(CLIENTS) not in sys.path:
    sys.path.insert(0, str(CLIENTS))

from shellui_oauth_extra import SHELLUI_MCP_AUTHORIZE_QUERY_KEY, fetch_authorize_query_params  # noqa: E402

MCP_URL = os.environ.get('MCP_URL', 'http://localhost:8006/c/1/mcp')
IDENTITY_ORIGIN = os.environ.get('IDENTITY_ORIGIN', 'http://localhost:8001')
COMPOSE_FILE = os.environ.get('MCP_E2E_COMPOSE_FILE', '')
AI_ORIGIN = MCP_URL.rsplit('/c/', 1)[0]


def _fail(msg: str) -> None:
    raise SystemExit(f'[personal-saas] {msg}')


def check_saas_metadata() -> None:
    params = fetch_authorize_query_params(MCP_URL)
    if os.environ.get('MCP_E2E_EXPECT_SAAS_OFFERED', '1') == '1':
        if params.get('saas_offered') != '1':
            _fail(f'expected saas_offered=1 in {SHELLUI_MCP_AUTHORIZE_QUERY_KEY}, got {params!r}')
    meta = requests.get(f'{AI_ORIGIN}/.well-known/oauth-protected-resource/c/1/mcp', timeout=10)
    meta.raise_for_status()
    ext = meta.json().get(SHELLUI_MCP_AUTHORIZE_QUERY_KEY) or {}
    if ext.get('saas_offered') != '1':
        _fail(f'protected resource metadata missing saas_offered hint: {ext!r}')


def mint_personal_token() -> str:
    if not COMPOSE_FILE:
        _fail('MCP_E2E_COMPOSE_FILE required to mint personal token')
    script = """
from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.companies.models import Company
from apps.companies.access import set_company_access
from apps.agents.personal_agent_tokens import create_personal_agent_credential
User = get_user_model()
user = User.objects.filter(email='dev@localhost').first()
company = Company.objects.get(pk=1)
set_company_access(company, user, enabled=True)
exp = timezone.now() + timezone.timedelta(days=7)
_, access = create_personal_agent_credential(
    user=user,
    company=company,
    name='E2E personal',
    services=['ai', 'identity'],
    access_mode='read_only',
    read_level='safe',
    allow_destructive=False,
    expires_at=exp,
)
print(access)
"""
    proc = subprocess.run(
        ['docker', 'compose', '-f', COMPOSE_FILE, 'exec', '-T', 'identity', 'python', 'manage.py', 'shell'],
        input=script.encode(),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        _fail(proc.stderr.decode() or proc.stdout.decode() or 'personal token mint failed')
    lines = [ln.strip() for ln in proc.stdout.decode().splitlines() if ln.strip()]
    if not lines:
        _fail('personal token mint produced no output')
    return lines[-1]


def check_personal_gateway(token: str) -> None:
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json, text/event-stream',
        'Content-Type': 'application/json',
    }
    ok = requests.post(
        MCP_URL,
        headers=headers,
        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}),
        timeout=30,
    )
    if ok.status_code != 200:
        _fail(f'personal token tools/list on company 1: HTTP {ok.status_code}')
    wrong = requests.post(
        'http://localhost:8006/c/2/mcp',
        headers=headers,
        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}),
        timeout=30,
    )
    if wrong.status_code != 401:
        _fail(f'personal token on company 2 URL expected 401, got {wrong.status_code}')


def main() -> None:
    check_saas_metadata()
    token = mint_personal_token()
    check_personal_gateway(token)
    print('[personal-saas] SaaS authorize hint + personal token tenant isolation: ok')


if __name__ == '__main__':
    main()
