"""PKCE S256 helpers for MCP OAuth (RFC 7636). Ported from saas-service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

CHALLENGE_RE = re.compile(r'^[A-Za-z0-9\-_]{43,128}$')
VERIFIER_RE = re.compile(r'^[A-Za-z0-9\-._~]{43,128}$')


class PkceError(Exception):
    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(message)
        self.error_code = error_code


def new_verifier() -> str:
    return secrets.token_urlsafe(48)


def s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def parse_client_pkce(code_challenge, code_challenge_method, *, required: bool) -> str:
    challenge = (code_challenge or '').strip()
    method = (code_challenge_method or '').strip()
    if not challenge and not method:
        if required:
            raise PkceError('PKCE is required.', 'pkce_required')
        return ''
    if method != 'S256':
        raise PkceError('Only S256 is supported.', 'invalid_code_challenge_method')
    if not CHALLENGE_RE.match(challenge):
        raise PkceError('Invalid code_challenge.', 'invalid_code_challenge')
    return challenge


def verify_client_pkce(*, code_challenge: str | None, code_verifier: str | None, required: bool) -> tuple[str | None, str | None]:
    stored = (code_challenge or '').strip()
    verifier = (code_verifier or '').strip()
    if not stored:
        if required:
            return 'PKCE is required.', 'pkce_required'
        return None, None
    if not verifier or not VERIFIER_RE.match(verifier):
        return 'Invalid code_verifier.', 'invalid_code_verifier'
    computed = s256_challenge(verifier)
    if not hmac.compare_digest(computed, stored):
        return 'PKCE verification failed.', 'pkce_verification_failed'
    return None, None
