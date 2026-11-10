"""Small default MCP catalog: search, describe, and call without listing every tool.

Ranking is local and deterministic. It uses tool names, titles, descriptions, and a
fixed synonym list. It does not call an embedding service or any network.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from shellui_django.mcp.write_gate import decide_write

SEARCH_DEFAULT_LIMIT = 8
SEARCH_MAX_LIMIT = 20

# Always offered, and also appended to the full catalog so opt-in clients can see them.
DISCOVERY_ONLY_TOOLS = frozenset(
    {'ai_search_tools', 'ai_describe_tool', 'ai_call_tool', 'ai_get_approval'}
)

# Inventory reads an agent can use before it knows tool names. Omitted when that
# service is not connected. These are already in the 224-tool catalog.
DIRECT_READ_TOOLS = (
    'identity_list_users',
    'storage_list_bucket',
    'hosting_list_apps',
    'email_list_messages',
)

SERVICE_PROFILES: dict[str, dict[str, Any]] = {
    'ai': {
        'summary': 'Find a Shellui tool, then call it. Start here instead of loading every tool.',
        'examples': ['search tools to invite a user', 'describe identity_list_users', 'list connected services'],
    },
    'identity': {
        'summary': 'People, groups, invitations, sign-in, and the company event log.',
        'examples': ['invite a user', 'list users', 'who signed up last week'],
    },
    'storage': {
        'summary': 'Buckets, files, share links, and signed download URLs.',
        'examples': ['list buckets', 'make a file public', 'empty a bucket'],
    },
    'hosting': {
        'summary': 'Hosted apps, deployments, domains, and runtime logs.',
        'examples': ['list apps', 'deploy my app', 'roll back a deployment'],
    },
    'email': {
        'summary': 'Newsletters, broadcasts, templates, and outbound messages.',
        'examples': ['send a newsletter', 'list messages', 'rotate a webhook secret'],
    },
    'saas': {
        'summary': 'SaaS product tools for this company, when that service is connected.',
        'examples': ['list saas tools'],
    },
}

_ANNOTATIONS_READ = {
    'readOnlyHint': True,
    'destructiveHint': False,
    'idempotentHint': True,
    'openWorldHint': False,
}
_ANNOTATIONS_CALL = {
    'readOnlyHint': False,
    'destructiveHint': False,
    'idempotentHint': False,
    'openWorldHint': True,
}

_SECRET_KEY = re.compile(r'secret|password|token|api_key|authorization|credential', re.I)
_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_STOPWORDS = frozenset(
    {
        'a',
        'an',
        'the',
        'my',
        'your',
        'our',
        'to',
        'of',
        'for',
        'me',
        'please',
        'and',
        'or',
        'on',
        'in',
        'with',
        'this',
        'that',
        'from',
        'into',
        'un',
        'une',
        'le',
        'la',
        'les',
        'des',
        'du',
        'de',
        'et',
        'mon',
        'ma',
        'mes',
        'qui',
        'que',
        'est',
        'sont',
        'pour',
        'sur',
        'dans',
        'par',
        'tool',
        'tools',
        'api',
        'operation',
        'runs',
        'shellui',
    }
)
_SYNONYMS: dict[str, tuple[str, ...]] = {
    'invite': ('invitation', 'inviter', 'invitations'),
    'user': ('users', 'utilisateur', 'utilisateurs', 'membre', 'membres'),
    'company': ('companies', 'compagnie'),
    'signup': ('signed', 'inscrit', 'inscription', 'joined', 'signup'),
    'event': ('events', 'activity', 'journal', 'audit'),
    'deploy': ('deployment', 'deployments', 'deployer', 'deploiement', 'deploi'),
    'app': ('application', 'apps', 'site', 'sites'),
    'newsletter': ('newsletters', 'bulletin'),
    'send': ('envoyer', 'envoyez', 'sent'),
    'file': ('fichier', 'fichiers', 'object', 'objects'),
    'public': ('publique', 'publiquement'),
    'share': ('partage', 'partager', 'lien'),
    'secret': ('secrets', 'signing'),
    'webhook': ('webhooks',),
    'rotate': ('rotation', 'tourner'),
    'bucket': ('buckets',),
    'empty': ('vider', 'vide'),
    'message': ('messages', 'mail', 'mails'),
    'group': ('groups', 'groupe', 'groupes'),
    'rollback': ('revenir', 'annuler'),
    'domain': ('domains', 'domaine', 'domaines', 'hostname', 'hostnames'),
    'template': ('templates', 'modele'),
    'broadcast': ('broadcasts',),
}
_PHRASES: tuple[tuple[str, str], ...] = (
    ('signed up', ' signup '),
    ('sign up', ' signup '),
    ('s est inscrit', ' signup '),
    ('est inscrit', ' signup '),
    ('webhook secret', ' webhook secret rotate '),
    ('webhook signing', ' webhook secret rotate '),
    ('make a file public', ' file public share sign '),
    ('make public', ' public share sign '),
    ('file public', ' file public share sign '),
    ('fichier public', ' file public share sign '),
    ('rendre un fichier public', ' file public share sign '),
    ('rendre public', ' public share sign '),
    ('last week', ' recent '),
    ('cette semaine', ' recent '),
    ('la semaine', ' recent '),
    ('roll back', ' rollback '),
    ('who is in', ' user list '),
)
# (required expanded tokens, tool name or substring, bonus)
_INTENTS: tuple[tuple[frozenset[str], str, int], ...] = (
    (frozenset({'invite', 'user'}), 'identity_create_invitations', 700),
    (frozenset({'invite'}), 'identity_create_invitations', 450),
    (frozenset({'invite'}), 'invitation', 180),
    (frozenset({'signup'}), 'identity_list_events', 520),
    (frozenset({'signup'}), 'identity_list_users', 280),
    (frozenset({'recent', 'user'}), 'identity_list_events', 200),
    (frozenset({'deploy', 'app'}), 'hosting_create_apps_deployments', 700),
    (frozenset({'deploy'}), 'hosting_create_apps_deployments', 480),
    (frozenset({'deploy'}), 'deployments', 160),
    (frozenset({'rollback'}), 'hosting_create_apps_deployments_rollback', 700),
    (frozenset({'newsletter', 'send'}), 'email_broadcasts_send', 650),
    (frozenset({'newsletter', 'export'}), 'email_export_newsletter_subscribers', 800),
    (frozenset({'newsletter', 'rotate'}), 'email_rotate_newsletter_key', 800),
    (frozenset({'newsletter'}), 'email_create_newsletters', 420),
    (frozenset({'newsletter'}), 'newsletter', 200),
    (frozenset({'broadcast', 'send'}), 'email_broadcasts_send', 400),
    (frozenset({'file', 'public'}), 'storage_sign_object', 620),
    (frozenset({'file', 'public'}), 'storage_create_share', 540),
    (frozenset({'share'}), 'storage_create_share', 320),
    (frozenset({'upload'}), 'hosting_create_apps_deployments_artifact_upload_url', 450),
    (frozenset({'public', 'share'}), 'storage_create_share', 200),
    (frozenset({'secret', 'rotate'}), 'rotate_rule_secret', 560),
    (frozenset({'webhook', 'secret'}), 'rotate_rule_secret', 560),
    (frozenset({'empty', 'bucket'}), 'storage_empty_bucket', 700),
    (frozenset({'bucket'}), 'storage_list_bucket', 220),
    (frozenset({'message'}), 'email_list_messages', 280),
    (frozenset({'group'}), 'identity_list_groups', 200),
    (frozenset({'group', 'create'}), 'identity_create_groups', 400),
    (frozenset({'user', 'delete'}), 'identity_delete_users', 700),
    (frozenset({'invite', 'revoke'}), 'identity_revoke_invitations', 700),
    (frozenset({'domain'}), 'hosting_list_apps_domains', 500),
    (frozenset({'domains'}), 'hosting_list_apps_domains', 500),
    (frozenset({'send', 'test'}), 'email_send_test_templates', 450),
    (frozenset({'company', 'get'}), 'identity_get_companies', 500),
    (frozenset({'user'}), 'identity_list_users', 160),
    (frozenset({'create', 'app'}), 'hosting_create_apps', 350),
    (frozenset({'event'}), 'identity_list_events', 180),
    (frozenset({'events'}), 'identity_list_events', 220),
    (frozenset({'app'}), 'hosting_list_apps', 140),
)
_TIME_HINTS = frozenset({'recent', 'yesterday', 'today', 'week', 'aujourd', 'hier'})
_WRITE_HINTS = frozenset({'create', 'invite', 'send', 'delete', 'deploy', 'rotate', 'empty', 'make', 'update', 'revoke'})


def fold_text(value: str) -> str:
    """Lowercase and strip accents so French queries match English tool copy."""
    normalized = unicodedata.normalize('NFKD', str(value or ''))
    stripped = ''.join(ch for ch in normalized if not unicodedata.combining(ch))
    return stripped.lower().replace("'", ' ').replace('’', ' ')


def redact_arguments(value: Any) -> Any:
    """Mask secret-shaped fields before they are shown to a person."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                redacted[key] = '***'
            else:
                redacted[key] = redact_arguments(item)
        return redacted
    if isinstance(value, list):
        return [redact_arguments(item) for item in value]
    return value


def arguments_preview(arguments: dict[str, Any] | None) -> str:
    if not isinstance(arguments, dict) or not arguments:
        return ''
    text = json.dumps(redact_arguments(arguments), sort_keys=True, default=str, ensure_ascii=True)
    if len(text) > 400:
        text = text[:400] + '...'
    return f'Arguments: {text}'


def discovery_tool_definitions() -> list[dict[str, Any]]:
    """Search, describe, and call. ``ai_list_services`` stays the OpenAPI tool."""
    return [
        {
            'name': 'ai_search_tools',
            'title': 'AI: Search tools',
            'description': (
                'Search Shellui tools with a short phrase. Returns the best matches with '
                'read, write, destructive, and approval flags plus the full input schema, '
                'so you can call a match immediately. Optional filters: service '
                '(identity, storage, hosting, email) and access (read or write). '
                'limit defaults to 8. Then call the tool, or pass it to ai_call_tool.'
            ),
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'query': {
                        'type': 'string',
                        'description': 'What you want to do, or an exact tool name.',
                    },
                    'service': {
                        'type': 'string',
                        'description': 'Optional service id: identity, storage, hosting, email, or saas.',
                    },
                    'access': {
                        'type': 'string',
                        'enum': ['read', 'write'],
                        'description': 'Optional. read keeps read-only tools. write keeps tools that change data.',
                    },
                    'limit': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': SEARCH_MAX_LIMIT,
                        'description': f'How many matches to return. Default {SEARCH_DEFAULT_LIMIT}, maximum {SEARCH_MAX_LIMIT}.',
                    },
                },
                'required': ['query'],
            },
            'annotations': dict(_ANNOTATIONS_READ),
        },
        {
            'name': 'ai_describe_tool',
            'title': 'AI: Describe tool',
            'description': (
                'Return the full input schema, access flags, and a short usage note for one '
                'or more Shellui gateway tool names. Use this when a search result is not enough. '
                'Then call the tool directly or through ai_call_tool.'
            ),
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'names': {
                        'type': 'array',
                        'items': {'type': 'string'},
                        'minItems': 1,
                        'maxItems': 8,
                        'description': 'Gateway tool names, for example identity_list_users.',
                    },
                    'name': {
                        'type': 'string',
                        'description': 'One tool name. Use names when you need more than one.',
                    },
                },
            },
            'annotations': dict(_ANNOTATIONS_READ),
        },
        {
            'name': 'ai_call_tool',
            'title': 'AI: Call tool',
            'description': (
                'Run any Shellui gateway tool by name. arguments are the same object you would pass '
                'to tools/call. Tenant scope, approvals, secret masking, and audit logging '
                'are identical to a direct call. In ask mode the person sees the real tool '
                'name and arguments, not ai_call_tool.'
            ),
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Gateway tool name, for example identity_create_invitations.',
                    },
                    'arguments': {
                        'type': 'object',
                        'additionalProperties': True,
                        'description': 'Arguments for that tool. Use the input schema from search or describe.',
                    },
                },
                'required': ['name'],
            },
            'annotations': dict(_ANNOTATIONS_CALL),
        },
        {
            'name': 'ai_get_approval',
            'title': 'AI: Approval status',
            'description': (
                'Read one Shellui approval without running the tool. Pass the approval_id from a pending '
                'tool result. Returns status pending, approved, denied, or expired, plus the approval link '
                'and expiry when known. When status is approved, call the original tool again with the same '
                'arguments. That runs it once.'
            ),
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'approval_id': {
                        'type': 'string',
                        'description': 'Approval id from a pending tool result.',
                    },
                },
                'required': ['approval_id'],
            },
            'annotations': dict(_ANNOTATIONS_READ),
        },
    ]


def tools_list_mode(request: Any, params: dict[str, Any] | None) -> str:
    """``discovery`` unless the URL, the list params, or the server setting asks for ``all``."""
    from django.conf import settings

    configured = str(getattr(settings, 'MCP_TOOLS_LIST_MODE', 'discovery') or 'discovery').strip().lower()
    if configured == 'all':
        return 'all'
    if request is not None:
        query = ''
        getter = getattr(request, 'GET', None)
        if getter is not None:
            query = str(getter.get('tools') or '').strip().lower()
        if query == 'all':
            return 'all'
    listed = str((params or {}).get('tools') or '').strip().lower()
    if listed == 'all':
        return 'all'
    return 'discovery'


def listed_tools(full_catalog: list[dict[str, Any]], *, mode: str, company_label: str) -> list[dict[str, Any]]:
    """Default list is discovery. ``all`` is the operational catalog plus search, describe, and call."""
    from apps.connector.mcp_tool_presentation import apply_gateway_tool_presentation

    extras = [
        apply_gateway_tool_presentation(tool, company_label=company_label)
        for tool in discovery_tool_definitions()
    ]
    if mode == 'all':
        present = {str(tool.get('name') or '') for tool in full_catalog}
        return list(full_catalog) + [tool for tool in extras if tool['name'] not in present]
    by_name = {str(tool.get('name') or ''): tool for tool in full_catalog}
    listed: list[dict[str, Any]] = []
    services = by_name.get('ai_list_services')
    if services is not None:
        listed.append(services)
    listed.extend(extras)
    for name in DIRECT_READ_TOOLS:
        tool = by_name.get(name)
        if tool is not None:
            listed.append(tool)
    return listed


def enrich_service_rows(
    services: list[dict[str, str]],
    catalog: list[dict[str, Any]] | None,
    *,
    include_counts: bool = True,
) -> list[dict[str, Any]]:
    """Add a one-line summary and example tasks. Counts are omitted when the catalog is cold."""
    counts: dict[str, int] = {}
    for tool in catalog or []:
        name = str(tool.get('name') or '')
        if name in DISCOVERY_ONLY_TOOLS:
            continue
        service_id = name.split('_', 1)[0]
        counts[service_id] = counts.get(service_id, 0) + 1
    rows: list[dict[str, Any]] = []
    ai_profile = SERVICE_PROFILES['ai']
    ai_row: dict[str, Any] = {
        'id': 'ai',
        'name': 'AI',
        'summary': ai_profile['summary'],
        'examples': list(ai_profile['examples']),
    }
    if include_counts:
        ai_row['tool_count'] = counts.get('ai', 0) + len(DISCOVERY_ONLY_TOOLS)
    rows.append(ai_row)
    for item in services:
        service_id = str(item.get('id') or '')
        profile = SERVICE_PROFILES.get(service_id, {})
        row = dict(item)
        row['summary'] = profile.get('summary') or f'{item.get("name") or service_id} tools for this company.'
        row['examples'] = list(profile.get('examples') or [])
        if include_counts and catalog is not None:
            row['tool_count'] = counts.get(service_id, 0)
        rows.append(row)
    return rows


def _ranking_copy(value: str) -> str:
    text = str(value or '')
    marker = 'not from tool arguments.'
    if marker in text:
        text = text.split(marker, 1)[1]
    return text


def _synonym_group(token: str) -> set[str]:
    for canonical, aliases in _SYNONYMS.items():
        group = {canonical, *aliases}
        if token in group:
            return group
    if len(token) >= 4:
        for canonical, aliases in _SYNONYMS.items():
            group = {canonical, *aliases}
            if any(_edit_distance(token, item) == 1 and len(item) >= 4 for item in group):
                return group
    return set()


def _expand_tokens(text: str) -> set[str]:
    folded = fold_text(text)
    for source, target in _PHRASES:
        folded = folded.replace(source, target)
    raw = [token for token in _TOKEN_RE.findall(folded) if token not in _STOPWORDS and len(token) > 1]
    expanded = set(raw)
    for token in list(raw):
        expanded |= _synonym_group(token)
    return expanded


def _edit_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if abs(len(left) - len(right)) > 2:
        return 3
    previous = list(range(len(right) + 1))
    for index, char in enumerate(left, 1):
        current = [index]
        for inner, other in enumerate(right, 1):
            current.append(
                min(
                    current[inner - 1] + 1,
                    previous[inner] + 1,
                    previous[inner - 1] + (char != other),
                )
            )
        previous = current
    return previous[-1]


def _tool_blob(tool: dict[str, Any]) -> tuple[str, set[str], set[str]]:
    name = str(tool.get('name') or '')
    title = fold_text(_ranking_copy(str(tool.get('title') or '')))
    description = fold_text(_ranking_copy(str(tool.get('description') or '')))
    folded_name = fold_text(name)
    name_tokens = set(part for part in folded_name.split('_') if part)
    name_tokens.add(folded_name)
    text_tokens = set(_TOKEN_RE.findall(f'{title} {description}'))
    return name, name_tokens, text_tokens


def rank_tools(
    catalog: list[dict[str, Any]],
    query: str,
    *,
    service: str | None = None,
    access: str | None = None,
    limit: int = SEARCH_DEFAULT_LIMIT,
) -> list[tuple[int, dict[str, Any]]]:
    """Return ``(score, tool)`` best first. Ties break by tool name."""
    tokens = _expand_tokens(query)
    folded_query = fold_text(query).strip()
    compact = re.sub(r'[^a-z0-9_]+', '', folded_query)
    service_id = fold_text(service or '').strip()
    access_mode = fold_text(access or '').strip()
    scored: list[tuple[int, str, dict[str, Any]]] = []
    for tool in catalog:
        name, name_tokens, text_tokens = _tool_blob(tool)
        if not name or name in DISCOVERY_ONLY_TOOLS:
            continue
        if service_id and not name.startswith(f'{service_id}_'):
            continue
        read_only, destructive = _traits(tool)
        if access_mode == 'read' and not read_only:
            continue
        if access_mode == 'write' and read_only:
            continue
        score = 0
        if compact and compact == name:
            score += 10000
        elif compact and _edit_distance(compact, name) <= 2 and '_' in compact:
            score += 5000
        for token in tokens:
            if len(token) < 4 and token not in name_tokens:
                continue
            if token in name_tokens:
                score += 120
            elif len(token) >= 5 and any(_edit_distance(token, part) == 1 for part in name_tokens):
                score += 70
            if len(token) >= 4 and token in text_tokens:
                score += 30
        for required, needle, bonus in _INTENTS:
            if required <= tokens and (name == needle or needle in name):
                score += bonus
        if tokens & _TIME_HINTS:
            if name.split('_', 1)[-1].startswith(('list_', 'get_')) or '_list_' in name or name.startswith(
                tuple(f'{sid}_list_' for sid in ('identity', 'storage', 'hosting', 'email'))
            ):
                score += 80
        if tokens & _WRITE_HINTS:
            local = name.split('_', 1)[-1]
            if local.startswith(('create_', 'delete_', 'update_', 'replace_', 'revoke_', 'rotate_', 'empty')):
                score += 40
        if score <= 0:
            continue
        scored.append((score, name, tool))
    scored.sort(key=lambda row: (-row[0], row[1]))
    capped = max(1, min(int(limit or SEARCH_DEFAULT_LIMIT), SEARCH_MAX_LIMIT))
    return [(score, tool) for score, _name, tool in scored[:capped]]


def _traits(tool: dict[str, Any]) -> tuple[bool, bool]:
    meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
    annotations = tool.get('annotations') if isinstance(tool.get('annotations'), dict) else {}
    if 'read_only' in meta or 'destructive' in meta:
        return bool(meta.get('read_only')), bool(meta.get('destructive'))
    if 'read_only' in tool or 'destructive' in tool:
        return bool(tool.get('read_only')), bool(tool.get('destructive'))
    return bool(annotations.get('readOnlyHint')), bool(annotations.get('destructiveHint'))


def _needs_approval(tool: dict[str, Any], access_mode: str) -> bool:
    read_only, destructive = _traits(tool)
    meta = tool.get('_meta') if isinstance(tool.get('_meta'), dict) else {}
    method = str(meta.get('method') or ('GET' if read_only else 'POST')).upper()
    decision = decide_write(
        method=method,
        access_mode=access_mode or 'ask',
        destructive=destructive,
        allow_destructive_without_asking=False,
        tool_read_only=read_only,
    )
    return bool(decision.needs_approval)


def public_match(tool: dict[str, Any], *, access_mode: str) -> dict[str, Any]:
    read_only, destructive = _traits(tool)
    schema = tool.get('inputSchema') if isinstance(tool.get('inputSchema'), dict) else {'type': 'object'}
    return {
        'name': tool.get('name'),
        'title': tool.get('title') or tool.get('name'),
        'description': tool.get('description') or '',
        'service': str(tool.get('name') or '').split('_', 1)[0],
        'read_only': read_only,
        'destructive': destructive,
        'needs_approval': _needs_approval(tool, access_mode),
        'inputSchema': schema,
        'usage': 'Call this name with tools/call, or pass {name, arguments} to ai_call_tool.',
    }


def empty_search_hint(query: str, *, service: str | None, access: str | None) -> str:
    filters = []
    if service:
        filters.append(f'service {service}')
    if access:
        filters.append(f'access {access}')
    scope = f' with {" and ".join(filters)}' if filters else ''
    shown = fold_text(query).strip() or 'that query'
    return (
        f'No tools matched "{shown}"{scope}. '
        'Try a shorter phrase such as invite user, deploy app, newsletter, or bucket. '
        'Call ai_list_services to see which services this connection can use.'
    )


def parse_search_arguments(arguments: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    query = arguments.get('query')
    if not isinstance(query, str) or not query.strip():
        return None, 'Pass query as a short phrase or an exact tool name. Example: invite a user.'
    service = arguments.get('service')
    if service is not None:
        if not isinstance(service, str) or fold_text(service) not in SERVICE_PROFILES:
            known = ', '.join(sorted(sid for sid in SERVICE_PROFILES if sid != 'ai'))
            return None, f'service must be one of: {known}.'
        service = fold_text(service)
    access = arguments.get('access')
    if access is not None:
        if not isinstance(access, str) or fold_text(access) not in {'read', 'write'}:
            return None, 'access must be read or write.'
        access = fold_text(access)
    limit = arguments.get('limit', SEARCH_DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int):
        return None, f'limit must be an integer from 1 to {SEARCH_MAX_LIMIT}.'
    if limit < 1 or limit > SEARCH_MAX_LIMIT:
        return None, f'limit must be from 1 to {SEARCH_MAX_LIMIT}.'
    return {'query': query.strip(), 'service': service, 'access': access, 'limit': limit}, None


def search_payload(
    catalog: list[dict[str, Any]],
    arguments: dict[str, Any],
    *,
    access_mode: str,
) -> dict[str, Any]:
    parsed, error = parse_search_arguments(arguments)
    if error or parsed is None:
        return {'error': error or 'Search needs a query.', 'matches': []}
    ranked = rank_tools(
        catalog,
        parsed['query'],
        service=parsed['service'],
        access=parsed['access'],
        limit=parsed['limit'],
    )
    matches = [public_match(tool, access_mode=access_mode) for _score, tool in ranked]
    payload: dict[str, Any] = {'query': parsed['query'], 'matches': matches}
    if not matches:
        payload['hint'] = empty_search_hint(parsed['query'], service=parsed['service'], access=parsed['access'])
    return payload


def describe_payload(catalog: list[dict[str, Any]], arguments: dict[str, Any], *, access_mode: str) -> dict[str, Any]:
    names: list[str] = []
    raw_names = arguments.get('names')
    if isinstance(raw_names, list):
        names.extend(str(item).strip() for item in raw_names if str(item).strip())
    single = arguments.get('name')
    if isinstance(single, str) and single.strip():
        names.append(single.strip())
    if not names:
        return {
            'error': 'Pass name or names. Example: {"name": "identity_list_users"}.',
            'tools': [],
        }
    by_name = {str(tool.get('name') or ''): tool for tool in catalog}
    tools = []
    missing = []
    for name in names[:8]:
        tool = by_name.get(name)
        if tool is None:
            missing.append(name)
            continue
        tools.append(public_match(tool, access_mode=access_mode))
    payload: dict[str, Any] = {'tools': tools}
    if missing:
        suggestions = []
        for name in missing:
            ranked = rank_tools(catalog, name, limit=3)
            suggestions.append(
                {
                    'name': name,
                    'suggestions': [str(tool.get('name')) for _score, tool in ranked],
                }
            )
        payload['missing'] = suggestions
        payload['hint'] = 'Unknown names are listed in missing.suggestions. Search with ai_search_tools if none of them fit.'
    return payload


def suggest_tool_names(catalog: list[dict[str, Any]], query: str, *, limit: int = 3) -> list[str]:
    return [str(tool.get('name')) for _score, tool in rank_tools(catalog, query, limit=limit)]
