"""Who may connect to global MCP. Shellui accounts only."""

from __future__ import annotations

from typing import Any

_TERMS_KEYS = ('terms_accepted_at', 'tos_accepted_at', 'terms_accepted_version', 'terms_accepted')


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    text = str(value).strip()
    return bool(text) and text.lower() not in {'false', '0', 'no', 'off'}


def staff_refused(profile: dict | None, claims: dict | None = None) -> bool:
    """Refuse staff on the saas profile or on the identity token."""
    sources = []
    if isinstance(profile, dict):
        sources.append(profile)
    if isinstance(claims, dict):
        sources.append(claims)
        meta = claims.get('user_metadata')
        if isinstance(meta, dict):
            sources.append(meta)
    for source in sources:
        for flag in ('is_staff', 'is_superuser', 'is_global_staff'):
            if source.get(flag) is True:
                return True
    return False


def terms_accepted(profile: dict | None, claims: dict | None = None) -> bool:
    """Accept when a terms claim is truthy, or when the IdP does not emit any terms claim.

    Refuse only when a terms claim is present and falsy.
    """
    blobs: list[dict] = []
    if isinstance(profile, dict):
        blobs.append(profile)
    if isinstance(claims, dict):
        blobs.append(claims)
        for key in ('user_metadata', 'app_metadata'):
            meta = claims.get(key)
            if isinstance(meta, dict):
                blobs.append(meta)
    saw_key = False
    for blob in blobs:
        for key in _TERMS_KEYS:
            if key in blob:
                saw_key = True
                if _truthy(blob.get(key)):
                    return True
    return not saw_key
