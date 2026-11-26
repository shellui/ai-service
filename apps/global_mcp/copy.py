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
_BARE_TOOL = re.compile(r'(?<!tool )ai_get_approval')


def rewrite_relayed_approval_copy(value):
    """Rewrite regional approval instructions that tell an agent to call ai_get_approval.

    That name is not on the global endpoint. After the person approves the link,
    retry the same ai_call_company_tool call. Private keys starting with ``_``
    (tokens, relay sessions) are left untouched.
    """
    if isinstance(value, str):
        return _rewrite_approval_instruction(value)
    if isinstance(value, list):
        return [rewrite_relayed_approval_copy(item) for item in value]
    if isinstance(value, dict):
        return {
            key: value[key] if str(key).startswith('_') else rewrite_relayed_approval_copy(item)
            for key, item in value.items()
        }
    return value


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
        f'Call ai_call_company_tool again with the same company_id, tool, and arguments.',
    )
    text = text.replace(
        'Call ai_get_approval once (SSE holds until decided). After they approve, call the same tool again.',
        retry,
    )
    if 'ai_get_approval' in text:
        text = _BARE_TOOL.sub('ai_call_company_tool with tool ai_get_approval', text)
    return text
