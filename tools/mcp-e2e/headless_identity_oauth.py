#!/usr/bin/env python3
"""Complete Shellui MCP OAuth (magic link + consent) without a browser.

Uses identity-service HTTP endpoints only (same flow as MCP Inspector / ChatGPT). Magic-link
tokens are read from identity container stdout (ConsoleEmailBackend), which is DEBUG-only.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from urllib.parse import parse_qs, urljoin, urlparse

import requests

_CSRF_RE = re.compile(r'name="csrfmiddlewaretoken" value="([^"]+)"')
_TOKEN_RE = re.compile(r'token=([^&\s]+)')


def _csrf(html: str) -> str:
    match = _CSRF_RE.search(html)
    if not match:
        raise RuntimeError('csrf token not found in HTML response')
    return match.group(1)


def _magic_token_from_logs(compose_file: str, *, service: str = 'identity', since: str = '2m') -> str:
    proc = subprocess.run(
        ['docker', 'compose', '-f', compose_file, 'logs', '--no-log-prefix', '--since', since, service],
        capture_output=True,
        text=True,
        check=False,
    )
    text = (proc.stdout or '') + (proc.stderr or '')
    matches = _TOKEN_RE.findall(text)
    if not matches:
        raise RuntimeError(
            'magic link token not found in identity logs; expected ConsoleEmailBackend output with token='
        )
    return matches[-1]


def complete_mcp_oauth_authorization(
    authorization_url: str,
    *,
    identity_origin: str,
    email: str,
    company_id: int,
    compose_file: str,
    consent_services: list[str] | None = None,
) -> tuple[str, str | None]:
    """Return (authorization_code, state) after user consent."""
    session = requests.Session()
    session.headers.update({'User-Agent': 'shellui-mcp-e2e/1.0'})

    def get(url: str, **kwargs) -> requests.Response:
        return session.get(url, allow_redirects=True, timeout=30, **kwargs)

    def post(url: str, **kwargs) -> requests.Response:
        return session.post(url, allow_redirects=False, timeout=30, **kwargs)

    parsed = urlparse(authorization_url)
    if not parsed.scheme.startswith('http'):
        raise ValueError(f'expected http(s) authorization URL, got {authorization_url!r}')
    state = parse_qs(parsed.query).get('state', [None])[0]
    redirect_uri = parse_qs(parsed.query).get('redirect_uri', [None])[0]
    if not redirect_uri:
        raise RuntimeError('authorization URL missing redirect_uri')

    # Signed out: authorize redirects to sign-in.
    first = session.get(authorization_url, allow_redirects=False, timeout=30)
    if first.status_code in (302, 303) and '/oauth/mcp/signin' in (first.headers.get('Location') or ''):
        signin = get(urljoin(identity_origin, first.headers['Location']))
        signin_html = signin.text
        signin_url = signin.url
        try:
            token_before = _magic_token_from_logs(compose_file)
        except RuntimeError:
            token_before = ''
        post(
            urljoin(identity_origin, '/oauth/mcp/signin'),
            data={'email': email, 'csrfmiddlewaretoken': _csrf(signin_html)},
            headers={'Referer': signin_url},
        )
        # Wait for new log line with token=
        deadline = time.time() + 45
        raw_token = None
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                candidate = _magic_token_from_logs(compose_file, since='30s')
                if candidate != token_before:
                    raw_token = candidate
                    break
            except RuntimeError:
                continue
        if not raw_token:
            raise RuntimeError('timed out waiting for magic link email in identity logs')
        verify = post(
            urljoin(identity_origin, '/api/v1/magic-link/verify'),
            data={'token': raw_token, 'company_id': str(company_id)},
            headers={'Accept': 'text/html'},
        )
        if verify.status_code not in (302, 303):
            raise RuntimeError(f'magic-link verify failed: HTTP {verify.status_code} {verify.text[:200]}')
        authorize_after_login = verify.headers.get('Location') or authorization_url
        consent_page = get(authorize_after_login)
    elif first.status_code == 200:
        consent_page = first
    else:
        consent_page = get(authorization_url)

    if consent_page.status_code >= 400:
        raise RuntimeError(f'expected consent page, got HTTP {consent_page.status_code}')
    if 'Allow this MCP client' not in consent_page.text and 'decision' not in consent_page.text:
        raise RuntimeError('MCP consent page not shown after sign-in')

    # POST consent (approve) with same query params as authorize URL.
    form = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    form['csrfmiddlewaretoken'] = _csrf(consent_page.text)
    form['decision'] = 'approve'
    services = consent_services or ['identity', 'ai']
    payload = list(form.items()) + [('services', s) for s in services]
    approve = post(
        authorization_url,
        data=payload,
        headers={'Referer': authorization_url},
    )
    if approve.status_code not in (302, 303):
        raise RuntimeError(f'consent POST failed: HTTP {approve.status_code} {approve.text[:300]}')
    location = approve.headers.get('Location', '')
    if not location.startswith(redirect_uri):
        raise RuntimeError(f'unexpected redirect after consent: {location!r}')
    params = parse_qs(urlparse(location).query)
    code = params.get('code', [None])[0]
    if not code:
        raise RuntimeError(f'no code in redirect: {location!r}')
    return code, state


def main() -> int:
    parser = argparse.ArgumentParser(description='Headless Shellui MCP OAuth (magic link)')
    parser.add_argument('--authorization-url', required=True)
    parser.add_argument('--identity-origin', default='http://localhost:8001')
    parser.add_argument('--email', default='dev@localhost')
    parser.add_argument('--company-id', type=int, default=1)
    parser.add_argument('--compose-file', required=True)
    args = parser.parse_args()
    code, state = complete_mcp_oauth_authorization(
        args.authorization_url,
        identity_origin=args.identity_origin.rstrip('/'),
        email=args.email,
        company_id=args.company_id,
        compose_file=args.compose_file,
    )
    print(code)
    if state:
        print(state, file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
