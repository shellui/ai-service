"""User-facing sentences for global MCP. No dash punctuation."""

import re

REGION_ONLY_MESSAGE = (
    'ai.shellui.com/mcp is for Shellui accounts. '
    'If your company account lives in one region, copy its MCP URL from your Shellui dashboard instead.'
)

STAFF_MESSAGE = 'Staff accounts cannot authorize MCP agents.'

TERMS_MESSAGE = 'Accept the Shellui terms before connecting an agent.'

DOCS_URL = 'https://shellui.com/docs'

DESTROY_REFUSED = (
    'Global MCP does not delete a Shellui project. '
    'The project and its regional data stay in place.'
)


RETRY_COMPANY_TOOL = (
    'call ai_call_company_tool again with the same company_id, tool, and arguments'
)

_PENDING = re.compile(
    r'Call ai_get_approval once with this approval_id \(SSE holds until decided\)\.\s*'
    r'When status is approved, call \S+ again with the same arguments\.'
)
_TEXT_KEYS = frozenset({'instruction', 'message'})


def rewrite_relayed_approval_copy(value):
    """Rewrite regional approval instruction and message fields on a pending payload.

    Catalog results, including a tool named ai_get_approval, are left unchanged.
    After the person approves the link, retry the same ai_call_company_tool call.
    Private keys starting with ``_`` are left untouched.
    """
    if not _is_pending_approval(value):
        return value
    return _rewrite_approval_fields(value)


def _has_approval_url(value) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get('approval_url') or value.get('approval_required'):
        return True
    structured = value.get('structuredContent')
    return isinstance(structured, dict) and bool(structured.get('approval_url'))


def _is_pending_approval(value) -> bool:
    if not isinstance(value, dict):
        return False
    if _has_approval_url(value) or value.get('status') == 'pending':
        return True
    relay = value.get('relay') if isinstance(value.get('relay'), dict) else None
    if relay is not None:
        if _has_approval_url(relay) or _has_approval_url(relay.get('result')):
            return True
        elicitation = relay.get('elicitation')
        if isinstance(elicitation, dict) and (
            elicitation.get('url') or elicitation.get('mode') in {'url', 'form'}
        ):
            return True
    result = value.get('result') if isinstance(value.get('result'), dict) else None
    if result is None:
        return False
    if _has_approval_url(result) or result.get('status') == 'pending':
        return True
    structured = result.get('structuredContent')
    return isinstance(structured, dict) and (
        structured.get('status') == 'pending' or bool(structured.get('approval_url'))
    )


def _rewrite_approval_fields(value):
    if isinstance(value, list):
        return [_rewrite_approval_fields(item) for item in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, item in value.items():
        if str(key).startswith('_'):
            out[key] = item
        elif key in _TEXT_KEYS and isinstance(item, str):
            out[key] = _rewrite_approval_instruction(item)
        elif key == 'content' and isinstance(item, list):
            out[key] = [_rewrite_content_item(entry) for entry in item]
        elif isinstance(item, (dict, list)):
            out[key] = _rewrite_approval_fields(item)
        else:
            out[key] = item
    return out


def _rewrite_content_item(entry):
    if isinstance(entry, dict) and isinstance(entry.get('text'), str):
        rewritten = dict(entry)
        rewritten['text'] = _rewrite_approval_instruction(entry['text'])
        return rewritten
    return entry


def _rewrite_approval_instruction(text: str) -> str:
    if 'ai_get_approval' not in text:
        return text
    retry = f'After they approve, {RETRY_COMPANY_TOOL}.'
    text = _PENDING.sub(retry, text)
    text = text.replace(
        'call ai_get_approval (or retry the tool) to continue.',
        f'{RETRY_COMPANY_TOOL} to continue.',
    )
    text = text.replace(
        'Call the original tool again, or try ai_get_approval shortly.',
        'Call ai_call_company_tool again with the same company_id, tool, and arguments.',
    )
    text = text.replace(
        'Call ai_get_approval once (SSE holds until decided). After they approve, call the same tool again.',
        retry,
    )
    return text
