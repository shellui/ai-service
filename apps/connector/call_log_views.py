"""Lists of MCP tool-call logs stored by this gateway."""

from __future__ import annotations

from django.db.models import Q, QuerySet
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.authapi.permissions import IsMcpCallLogReader, IsPersonalAgentCallLogReader
from apps.connector.mcp_call_store import SERVICES
from apps.connector.models import McpCallLog

_STATUSES = frozenset(dict(McpCallLog.STATUSES))
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _positive_id(raw: object) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value < 1:
        return None
    return value


def owned_agent_call_logs(*, company_id: int, agent_id: str, user_id: int) -> QuerySet[McpCallLog]:
    """Rows for one agent in one company that belong to this user.

    ``owner_user_id`` is the regional user the agent acts for. Rows written
    before that column, or written from a token that omitted the claim, fall
    back to ``user_id`` when ``owner_user_id`` is empty. A set ``owner_user_id``
    is the only match for that row.
    """
    return McpCallLog.objects.filter(company_id=company_id, agent_id=agent_id).filter(
        Q(owner_user_id=user_id) | Q(owner_user_id__isnull=True, user_id=user_id)
    )


def _parse_bound(raw: str, *, name: str) -> tuple[object | None, Response | None]:
    text = str(raw or '').strip()
    if not text:
        return None, None
    parsed = parse_datetime(text)
    if parsed is None:
        return None, Response({'error': f'Invalid {name}.'}, status=400)
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed, None


def _row(row: McpCallLog) -> dict:
    item = {
        'id': row.id,
        'company_id': row.company_id,
        'agent_id': row.agent_id,
        'agent_name': row.agent_name,
        'client_id': row.client_id,
        'client_name': row.client_name,
        'token_kind': row.token_kind,
        'user_id': row.user_id,
        'user_email': row.user_email,
        'service': row.service,
        'tool_name': row.tool_name,
        'wrapper_tool': row.wrapper_tool,
        'operation_title': row.operation_title or row.tool_name or 'mcp_call',
        'access_kind': row.access_kind or 'unknown',
        'outcome': row.outcome or 'failed',
        'resource_label': row.resource_label or row.tool_name or '',
        'arguments': row.arguments_redacted or {},
        'status': row.status,
        'status_code': row.status_code,
        'error_code': row.error_code,
        'error_message': row.error_message,
        'duration_ms': row.duration_ms,
        'approval_id': row.approval_id,
        'approval_channel': row.approval_channel,
        'approval_outcome': row.approval_outcome,
        'created_at': row.created_at.isoformat(),
    }
    if row.global_agent_id or row.global_company_id:
        item['agent_audit_scope'] = 'global_company'
        item['global_agent_id'] = row.global_agent_id or None
        item['global_company_id'] = row.global_company_id or None
    return item


class McpCallLogRowSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    company_id = serializers.IntegerField()
    agent_id = serializers.CharField()
    agent_name = serializers.CharField()
    client_id = serializers.CharField()
    client_name = serializers.CharField()
    token_kind = serializers.CharField()
    user_id = serializers.IntegerField(allow_null=True)
    user_email = serializers.CharField()
    service = serializers.CharField()
    tool_name = serializers.CharField()
    wrapper_tool = serializers.CharField()
    operation_title = serializers.CharField()
    access_kind = serializers.ChoiceField(choices=['read', 'write', 'destructive', 'unknown'])
    outcome = serializers.ChoiceField(
        choices=['allowed', 'failed', 'denied', 'waiting_approval', 'session_used']
    )
    resource_label = serializers.CharField()
    arguments = serializers.JSONField()
    status = serializers.ChoiceField(choices=[choice[0] for choice in McpCallLog.STATUSES])
    status_code = serializers.IntegerField()
    error_code = serializers.CharField()
    error_message = serializers.CharField()
    duration_ms = serializers.IntegerField()
    approval_id = serializers.CharField()
    approval_channel = serializers.ChoiceField(choices=['form', 'link', 'none'])
    approval_outcome = serializers.CharField()
    created_at = serializers.DateTimeField()
    agent_audit_scope = serializers.CharField(required=False)
    global_agent_id = serializers.CharField(required=False, allow_null=True)
    global_company_id = serializers.CharField(required=False, allow_null=True)


class McpCallLogListSerializer(serializers.Serializer):
    count = serializers.IntegerField()
    limit = serializers.IntegerField()
    offset = serializers.IntegerField()
    call_logs = McpCallLogRowSerializer(many=True)


def _parse_page_filters(params, *, include_agent: bool) -> tuple[dict | None, Response | None]:
    agent = ''
    if include_agent:
        agent = str(params.get('agent') or '').strip()
        if agent and len(agent) > 128:
            return None, Response({'error': 'Invalid agent.'}, status=400)
    service = str(params.get('service') or '').strip().lower()
    tool = str(params.get('tool') or '').strip()
    status = str(params.get('status') or '').strip().lower()
    if service and service not in SERVICES:
        return None, Response({'error': 'Invalid service.'}, status=400)
    if tool and len(tool) > 255:
        return None, Response({'error': 'Invalid tool.'}, status=400)
    if status and status not in _STATUSES:
        return None, Response({'error': 'Invalid status.'}, status=400)
    created_after, err = _parse_bound(params.get('created_after'), name='created_after')
    if err is not None:
        return None, err
    created_before, err = _parse_bound(params.get('created_before'), name='created_before')
    if err is not None:
        return None, err
    try:
        limit = int(params.get('limit') or _DEFAULT_LIMIT)
        offset = int(params.get('offset') or 0)
    except (TypeError, ValueError):
        return None, Response({'error': 'Invalid limit or offset.'}, status=400)
    if limit < 1 or limit > _MAX_LIMIT or offset < 0:
        return None, Response({'error': 'Invalid limit or offset.'}, status=400)
    return {
        'agent': agent,
        'service': service,
        'tool': tool,
        'status': status,
        'created_after': created_after,
        'created_before': created_before,
        'limit': limit,
        'offset': offset,
    }, None


def _page(qs: QuerySet[McpCallLog], filters: dict) -> Response:
    if filters['agent']:
        qs = qs.filter(agent_id=filters['agent'])
    if filters['service']:
        qs = qs.filter(service=filters['service'])
    if filters['tool']:
        qs = qs.filter(tool_name=filters['tool'])
    if filters['status']:
        qs = qs.filter(status=filters['status'])
    if filters['created_after'] is not None:
        qs = qs.filter(created_at__gte=filters['created_after'])
    if filters['created_before'] is not None:
        qs = qs.filter(created_at__lt=filters['created_before'])
    limit = filters['limit']
    offset = filters['offset']
    count = qs.count()
    rows = qs.order_by('-created_at', '-id')[offset : offset + limit]
    return Response(
        {
            'count': count,
            'limit': limit,
            'offset': offset,
            'call_logs': [_row(row) for row in rows],
        }
    )


_LIST_FILTERS = [
    OpenApiParameter(
        'service',
        OpenApiTypes.STR,
        enum=sorted(SERVICES),
        description='identity, storage, hosting, email, saas, or ai.',
    ),
    OpenApiParameter('tool', OpenApiTypes.STR, description='Exact tool name.'),
    OpenApiParameter(
        'status',
        OpenApiTypes.STR,
        enum=sorted(_STATUSES),
        description='allowed, denied, waiting_approval, failed, or error.',
    ),
    OpenApiParameter(
        'created_after',
        OpenApiTypes.DATETIME,
        description='Inclusive ISO-8601 lower bound on created_at.',
    ),
    OpenApiParameter(
        'created_before',
        OpenApiTypes.DATETIME,
        description='Exclusive ISO-8601 upper bound on created_at.',
    ),
    OpenApiParameter('limit', OpenApiTypes.INT, description='Page size, 1 to 200. Default 50.'),
    OpenApiParameter('offset', OpenApiTypes.INT, description='Rows to skip. Default 0.'),
]


class McpCallLogListView(APIView):
    """Company-scoped call log for staff, company owners, and company admins.

    The company comes from the JWT. A token cannot read another company's rows.
    Agent access tokens are refused.
    """

    permission_classes = [IsMcpCallLogReader]

    @extend_schema(
        tags=['mcp-admin'],
        operation_id='ai_v1_mcp_call_logs_list',
        summary='List MCP agent tool-call logs',
        description=(
            'Returns tool calls recorded by the Shellui AI MCP gateway for the company '
            'on the caller JWT. Staff, company owners, and company admins only. '
            'A company admin is user_metadata.is_company_admin, or a group named '
            'admin, admins, or company admins, and does not have to be an owner. '
            'Agent access tokens are refused. '
            'Each row includes operation_title (tool name when no registry title), '
            'access_kind (read, write, destructive, or unknown), outcome '
            '(allowed, failed, denied, waiting_approval, or session_used), and '
            'resource_label. Global-company agents also include agent_audit_scope '
            'global_company, global_agent_id, and global_company_id when the token '
            'carried those ids. '
            'Filters: agent (agent id), service, tool (tool name), status, '
            'created_after (inclusive), created_before (exclusive). '
            'limit defaults to 50 and cannot exceed 200. offset defaults to 0.'
        ),
        parameters=[
            OpenApiParameter('agent', OpenApiTypes.STR, description='Exact agent id.'),
            *_LIST_FILTERS,
        ],
        responses={
            200: McpCallLogListSerializer,
            400: OpenApiResponse(description='Invalid filter.'),
            401: OpenApiResponse(description='Missing or invalid bearer token, including agent tokens.'),
            403: OpenApiResponse(
                description='Caller is not staff, a company owner, or a company admin, or has no company.'
            ),
        },
    )
    def get(self, request):
        user = request.user
        company_id = getattr(user, 'company_id', None)
        try:
            company_id = int(company_id)
        except (TypeError, ValueError):
            company_id = None
        if company_id is None or company_id < 1:
            return Response({'error': 'Forbidden'}, status=403)

        filters, err = _parse_page_filters(request.query_params, include_agent=True)
        if err is not None:
            return err
        return _page(McpCallLog.objects.filter(company_id=company_id), filters)


class PersonalAgentCallLogListView(APIView):
    """Call log for one agent the authenticated user owns.

    The user id and company id come from the app JWT. Staff, company owner,
    and company admin flags do not widen access. Agent access tokens are refused.
    An agent with no row attributed to the caller returns 404.
    """

    permission_classes = [IsPersonalAgentCallLogReader]

    @extend_schema(
        tags=['mcp-personal'],
        operation_id='ai_v1_mcp_personal_agent_call_logs_list',
        summary='List MCP tool-call logs for your agent',
        description=(
            'Returns tool calls recorded by the Shellui AI MCP gateway for one agent '
            'the caller owns. Authentication is a bearer app JWT, the same verifier as '
            'GET /ai/v1/mcp/call-logs. Any authenticated member may call this route. '
            'Staff, company owner, and company admin flags grant access only when that '
            'same user owns the agent. Agent access tokens are refused. '
            'The user id and company id come from the JWT. The agent id is the path. '
            'A row is attributed when owner_user_id equals that user. Rows with an empty '
            'owner_user_id are attributed when user_id equals that user. '
            'When the caller has no attributed row for this agent in their company, '
            'the response is 404. '
            'Filters: service, tool (tool name), status, created_after (inclusive), '
            'created_before (exclusive). limit defaults to 50 and cannot exceed 200. '
            'offset defaults to 0. Arguments are the redacted copy stored at insert. '
            'MCP is in Beta.'
        ),
        parameters=[
            OpenApiParameter(
                'agent_id',
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description='Agent id. The caller must own this agent.',
            ),
            *_LIST_FILTERS,
        ],
        responses={
            200: McpCallLogListSerializer,
            400: OpenApiResponse(description='Invalid filter.'),
            401: OpenApiResponse(description='Missing or invalid bearer token, including agent tokens.'),
            403: OpenApiResponse(description='Agent access token.'),
            404: OpenApiResponse(description='No call log row for this agent is attributed to the caller.'),
        },
    )
    def get(self, request, agent_id: str):
        filters, err = _parse_page_filters(request.query_params, include_agent=False)
        if err is not None:
            return err
        agent_id = str(agent_id or '').strip()
        user_id = _positive_id(getattr(request.user, 'user_id', None))
        company_id = _positive_id(getattr(request.user, 'company_id', None))
        if user_id is None or company_id is None or not agent_id or len(agent_id) > 128:
            return Response({'error': 'Not found.'}, status=404)
        owned = owned_agent_call_logs(company_id=company_id, agent_id=agent_id, user_id=user_id)
        if not owned.exists():
            return Response({'error': 'Not found.'}, status=404)
        return _page(owned, filters)
