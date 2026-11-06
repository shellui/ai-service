"""Strict numeric company_id parsing for MCP (fail closed on UUID-as-company confusion)."""

from __future__ import annotations

import re
from typing import Any

# Typical string form of a company UUID incorrectly used where an integer id is required.
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


def strict_numeric_company_id(raw: Any) -> int | None:
    """
    Return a non-negative integer company_id, or None when the value is missing,
    non-numeric, or looks like a global/company UUID string.
    """
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        if _UUID_RE.match(s):
            return None
        try:
            return int(s, 10)
        except ValueError:
            return None
    return None
