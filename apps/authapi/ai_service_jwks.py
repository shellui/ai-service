"""RSA signing key and JWKS for ai-service delegation JWTs."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from django.core.exceptions import ImproperlyConfigured

MIN_RSA_KEY_SIZE = 2048


@dataclass(frozen=True)
class AiServiceSigningKey:
    kid: str
    private_pem: str
    public_pem: str
    algorithm: str = 'RS256'


def normalize_pem(value: str) -> str:
    pem = (value or '').strip()
    if not pem:
        return ''
    for _ in range(4):
        before = pem
        pem = pem.strip()
        if len(pem) >= 2 and pem[0] == pem[-1] and pem[0] in {'"', "'"}:
            pem = pem[1:-1]
            continue
        if '\\n' in pem:
            pem = pem.replace('\\n', '\n')
        if '\\r' in pem:
            pem = pem.replace('\\r', '\r')
        pem = pem.replace('\r\n', '\n').strip()
        if pem == before:
            break
    return pem


def _int_to_base64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, 'big')).rstrip(b'=').decode('ascii')


def compute_rsa_kid(public_pem: str) -> str:
    public_key = load_pem_public_key(public_pem.encode(), backend=default_backend())
    numbers = public_key.public_numbers()
    canonical = json.dumps(
        {'e': _int_to_base64url(numbers.e), 'kty': 'RSA', 'n': _int_to_base64url(numbers.n)},
        separators=(',', ':'),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def _load_rsa_private_key(pem: str):
    try:
        key = load_pem_private_key(pem.encode(), password=None, backend=default_backend())
    except ValueError as exc:
        raise ImproperlyConfigured('AI_SERVICE_SIGNING_KEY is not a valid RSA PEM private key.') from exc
    if key.key_size < MIN_RSA_KEY_SIZE:
        raise ImproperlyConfigured(
            f'AI_SERVICE_SIGNING_KEY must be at least {MIN_RSA_KEY_SIZE} bits (got {key.key_size}).'
        )
    return key


def public_pem_from_private(private_pem: str) -> str:
    private_key = _load_rsa_private_key(private_pem)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_bytes.decode()


def rsa_public_key_to_jwk(public_pem: str, kid: str) -> dict:
    public_key = load_pem_public_key(public_pem.encode(), backend=default_backend())
    numbers = public_key.public_numbers()
    return {
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'kid': kid,
        'n': _int_to_base64url(numbers.n),
        'e': _int_to_base64url(numbers.e),
    }


def generate_rsa_key_pair(key_size: int = 3072) -> tuple[str, str]:
    if key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(f'RSA key size must be at least {MIN_RSA_KEY_SIZE} bits.')
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def load_ai_service_signing_key(*, private_pem: str, kid: str = '') -> AiServiceSigningKey:
    private_pem = normalize_pem(private_pem)
    if not private_pem:
        raise ImproperlyConfigured('AI_SERVICE_SIGNING_KEY is required for RS256 delegation.')
    _load_rsa_private_key(private_pem)
    public_pem = public_pem_from_private(private_pem)
    resolved_kid = (kid or '').strip() or compute_rsa_kid(public_pem)
    return AiServiceSigningKey(kid=resolved_kid, private_pem=private_pem, public_pem=public_pem)


def build_jwks_document(signing_key: AiServiceSigningKey) -> dict:
    return {'keys': [rsa_public_key_to_jwk(signing_key.public_pem, signing_key.kid)]}
