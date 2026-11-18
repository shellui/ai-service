"""User-facing sentences for global MCP. No dash punctuation."""

REGION_ONLY_MESSAGE = (
    'ai.shellui.com/mcp is for Shellui accounts. '
    "If your company account is in one region, connect your region's AI URL instead: "
    'https://<regional ai>/c/<company_id>/mcp.'
)

STAFF_MESSAGE = 'Staff accounts cannot authorize MCP agents.'

TERMS_MESSAGE = 'Accept the Shellui terms before connecting an agent.'

DOCS_URL = 'https://shellui.com/docs'

DESTROY_REFUSED = (
    'Global MCP does not delete a Shellui project. '
    'The project and its regional data stay in place.'
)
