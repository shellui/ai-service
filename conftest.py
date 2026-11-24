"""Pytest bootstrap. Settings import needs a secret before Django starts."""

from __future__ import annotations

import os


def pytest_load_initial_conftests(early_config, parser, args):
    del early_config, parser, args
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    os.environ.setdefault('SECRET_KEY', 'ci-only-not-for-production-0123456789abcdef')
    os.environ.setdefault('DEBUG', 'true')
    os.environ.setdefault('IDENTITY_JWKS_URL', 'http://localhost:8000/.well-known/jwks.json')
