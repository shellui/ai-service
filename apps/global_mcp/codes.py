"""Authorization code hashing. The raw code is returned once and never stored."""

from __future__ import annotations

import hashlib
import secrets


def issue_code() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, hash_code(raw)


def hash_code(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()
