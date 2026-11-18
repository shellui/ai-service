"""Which approval channel a tool uses: in-chat form, or the identity page link.

Destructive tools always use the link. A company can force the link for every
other tool. There is no per-company approval model on identity or in this
service, so the override is ``MCP_APPROVAL_CHANNEL_BY_COMPANY``.
"""

from __future__ import annotations

import json
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

CHANNEL_FORM = 'form'
CHANNEL_LINK = 'link'


def company_channel_override(company_id: int) -> str | None:
    """``form`` or ``link`` for this company, or None when the default applies."""
    raw = str(getattr(settings, 'MCP_APPROVAL_CHANNEL_BY_COMPANY', '') or '').strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning('MCP approval channel override is not valid JSON')
        return None
    if not isinstance(data, dict):
        return None
    value = str(data.get(str(int(company_id))) or data.get(int(company_id)) or '').strip().lower()
    if value in {CHANNEL_FORM, CHANNEL_LINK}:
        return value
    return None


def approval_channel(*, destructive: bool, company_id: int, form_supported: bool) -> str:
    """Default from the tool: destructive uses the link. Other tools use form when the client declared it.

    A company override of ``link`` forces the page for non-destructive tools too.
    An override of ``form`` cannot turn a destructive tool into an in-chat approval.
    """
    if destructive or not form_supported:
        return CHANNEL_LINK
    if company_channel_override(company_id) == CHANNEL_LINK:
        return CHANNEL_LINK
    return CHANNEL_FORM
