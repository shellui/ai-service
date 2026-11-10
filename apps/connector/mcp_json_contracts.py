"""JSON Schema stand-ins for OpenAPI object fields that drf-spectacular leaves untyped.

Email documents, themes, translations, and placeholder maps, and the identity user
``data`` merge, are real objects. A bare ``JSONField`` is ``{}`` in OpenAPI, and
wrapping that as ``additionalProperties: true`` fails the MCP schema audit. These
contracts match the validators in email-service and identity-service. When those
services publish a typed schema, conversion uses that schema instead.
"""

from __future__ import annotations

from typing import Any

# Deepest TipTap node observed in the email library seeds (root = 0).
EMAIL_DOCUMENT_DEPTH = 27

_THEME_ROLES = (
    'background',
    'foreground',
    'card',
    'muted',
    'muted_foreground',
    'primary',
    'primary_foreground',
    'border',
)

_STRING_ATTRS = (
    'align',
    'alignment',
    'alt',
    'border',
    'cellpadding',
    'cellspacing',
    'class',
    'data-id',
    'dir',
    'href',
    'lang',
    'src',
    'style',
    'textId',
    'width',
)

_INT_ATTRS = ('height', 'level')


def _string(description: str) -> dict[str, Any]:
    return {'type': 'string', 'description': description}


def _object(description: str, properties: dict[str, Any], *, additional: Any = False, required: list[str] | None = None) -> dict[str, Any]:
    node: dict[str, Any] = {
        'type': 'object',
        'description': description,
        'properties': properties,
        'additionalProperties': additional,
    }
    if required:
        node['required'] = required
    return node


def _email_attrs() -> dict[str, Any]:
    properties: dict[str, Any] = {
        name: _string(f'Attribute `{name}`.')
        for name in _STRING_ATTRS
    }
    properties['width'] = _string('CSS length such as 100%, or a pixel count sent as text.')
    for name in _INT_ATTRS:
        properties[name] = {'type': 'integer', 'description': f'Attribute `{name}`.'}
    return _object(
        'Node attributes such as href, src, style, textId, level, and width.',
        properties,
        additional={'type': 'string', 'description': 'Other attribute value.'},
    )


def _email_mark() -> dict[str, Any]:
    return _object(
        'Inline mark such as link, bold, italic, or preservedStyle.',
        {
            'type': _string('Mark type.'),
            'attrs': _email_attrs(),
        },
    )


def email_document_node(depth: int = EMAIL_DOCUMENT_DEPTH) -> dict[str, Any]:
    """One TipTap node. ``depth`` is how many further ``content`` levels stay fully typed."""
    properties: dict[str, Any] = {
        'type': _string('Node type. The root node is doc. Other nodes include paragraph, text, heading, table, button, and image.'),
        'text': _string('Text content when type is text.'),
        'attrs': _email_attrs(),
        'marks': {
            'type': 'array',
            'description': 'Inline marks on a text node.',
            'items': _email_mark(),
        },
    }
    if depth > 0:
        items: dict[str, Any] = email_document_node(depth - 1)
    else:
        items = _object(
            'Deeper document node. Further children repeat type, text, attrs, marks, and content.',
            {'type': _string('Node type.')},
            additional={'type': 'string', 'description': 'Nested field on a deeper node.'},
        )
    properties['content'] = {
        'type': 'array',
        'description': 'Child nodes in reading order. Each child uses the same keys as this node.',
        'items': items,
    }
    return _object(
        'TipTap email document node. The root type is doc.',
        properties,
        required=['type'],
    )


def email_theme_schema(description: str = '') -> dict[str, Any]:
    colors = _object(
        'Hex colors for theme roles. Omit a role to keep the design color.',
        {role: _string(f'Hex color for the {role} role, for example #0a66c2.') for role in _THEME_ROLES},
    )
    text = description.strip() or (
        'Colors that repaint a library design. Empty object keeps the design colors.'
    )
    return _object(
        text,
        {
            'name': _string('Theme name.'),
            'label': _string('Human-readable theme label.'),
            'colors': colors,
        },
    )


def _translation_inline_node() -> dict[str, Any]:
    return _object(
        'Inline translation node (text or hardBreak).',
        {
            'type': _string('Inline node type: text or hardBreak.'),
            'text': _string('Translated text when type is text.'),
            'marks': {
                'type': 'array',
                'description': 'Optional inline marks on the translated text.',
                'items': _email_mark(),
            },
        },
    )


def email_translations_schema(description: str = '') -> dict[str, Any]:
    def entry() -> dict[str, Any]:
        block = _object(
            'Translated text for one block, matched by attrs.textId.',
            {
                'content': {
                    'type': 'array',
                    'description': 'Inline nodes that replace the block text.',
                    'items': _translation_inline_node(),
                },
                'source': _string('Fingerprint of the source text this translation was made from.'),
            },
        )
        return _object(
            'Subject, preheader, and block text for one language.',
            {
                'subject': _string('Translated subject. Empty falls back to the main subject.'),
                'preheader': _string('Translated preheader. Empty falls back to the main preheader.'),
                'blocks': _object(
                    'Block translations keyed by attrs.textId.',
                    {},
                    additional=block,
                ),
            },
        )

    text = description.strip() or 'Other languages of this copy. Keys are language codes en and fr.'
    return _object(text, {'en': entry(), 'fr': entry()})


def email_variables_schema(description: str = '') -> dict[str, Any]:
    text = description.strip() or 'Placeholder map for {{ token }} values. Omitted keys use catalog examples where available.'
    return _object(
        text,
        {},
        additional=_string('Text substituted for this placeholder token.'),
    )


def identity_user_metadata_schema(description: str = '') -> dict[str, Any]:
    preferences = _object(
        'UI preferences merged into user_metadata.shelluiPreferences.',
        {
            'themeName': _string('Theme name.'),
            'language': {
                'type': 'string',
                'enum': ['en', 'fr'],
                'description': 'UI language.',
            },
            'region': _string('Region code.'),
            'colorScheme': {
                'type': 'string',
                'enum': ['light', 'dark', 'system'],
                'description': 'Color scheme.',
            },
        },
    )
    text = description.strip() or (
        'Partial user_metadata merge. Extra string keys are kept. '
        'is_staff, is_superuser, is_company_owner, and groups are ignored.'
    )
    return _object(
        text,
        {
            'name': _string('Display name stored in user_metadata.'),
            'full_name': _string('Full name stored in user_metadata.'),
            'avatar_url': _string('Profile image URL.'),
            'shelluiPreferences': preferences,
        },
        additional=_string('Other user_metadata string value, for example nickname.'),
    )


def contract_for_untyped_field(name: str, description: str, sibling_names: set[str]) -> dict[str, Any] | None:
    """Return a typed schema for a bare JSONField, or None to keep the generic fallback."""
    if name == 'document':
        node = email_document_node()
        if description.strip():
            node = {**node, 'description': f'{description.strip()} {node["description"]}'.strip()}
        return node
    if name == 'theme':
        return email_theme_schema(description)
    if name == 'translations':
        return email_translations_schema(description)
    if name == 'variables':
        return email_variables_schema(description)
    if name == 'data' and {'first_name', 'group_ids'} <= sibling_names:
        return identity_user_metadata_schema(description)
    return None
