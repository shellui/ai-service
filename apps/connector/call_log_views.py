"""Company admin list of MCP tool-call logs stored by this gateway."""

from __future__ import annotations

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.authapi.permissions import IsStaffOrCompanyOwner
from apps.connector.mcp_call_store import SERVICES
from apps.connector.models import McpCallLog

_STATUSES = frozenset(dict(McpCallLog.STATUSES))
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


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
    return {
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


class McpCallLogListView(APIView):
    """Company-scoped call log for staff and company owners.

    The company comes from the JWT. A token cannot read another company's rows.
    Agent access tokens are not accepted by this authentication class.
    """

    permission_classes = [IsStaffOrCompanyOwner]

    @extend_schema(
        tags=['mcp-admin'],
        operation_id='ai_v1_mcp_call_logs_list',
        summary='List MCP agent tool-call logs',
        description=(
            'Returns tool calls recorded by the Shellui AI MCP gateway for the company '
            'on the caller JWT. Staff and company owners only. '
            'Filters: agent (agent id), service, tool (tool name), status, '
            'created_after (inclusive), created_before (exclusive). '
            'limit defaults to 50 and cannot exceed 200. offset defaults to 0.'
        ),
        parameters=[
            OpenApiParameter('agent', OpenApiTypes.STR, description='Exact agent id.'),
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
        ],
        responses={
            200: OpenApiResponse(description='Matching call logs for this company.'),
            400: OpenApiResponse(description='Invalid filter.'),
            401: OpenApiResponse(description='Missing or invalid bearer token.'),
            403: OpenApiResponse(description='Caller is not staff or a company owner, or has no company.'),
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

        params = request.query_params
        agent = str(params.get('agent') or '').strip()
        service = str(params.get('service') or '').strip().lower()
        tool = str(params.get('tool') or '').strip()
        status = str(params.get('status') or '').strip().lower()
        if agent and len(agent) > 128:
            return Response({'error': 'Invalid agent.'}, status=400)
        if service and service not in SERVICES:
            return Response({'error': 'Invalid service.'}, status=400)
        if tool and len(tool) > 255:
            return Response({'error': 'Invalid tool.'}, status=400)
        if status and status not in _STATUSES:
            return Response({'error': 'Invalid status.'}, status=400)
        created_after, err = _parse_bound(params.get('created_after'), name='created_after')
        if err is not None:
            return err
        created_before, err = _parse_bound(params.get('created_before'), name='created_before')
        if err is not None:
            return err

        try:
            limit = int(params.get('limit') or _DEFAULT_LIMIT)
            offset = int(params.get('offset') or 0)
        except (TypeError, ValueError):
            return Response({'error': 'Invalid limit or offset.'}, status=400)
        if limit < 1 or limit > _MAX_LIMIT or offset < 0:
            return Response({'error': 'Invalid limit or offset.'}, status=400)

        qs = McpCallLog.objects.filter(company_id=company_id)
        if agent:
            qs = qs.filter(agent_id=agent)
        if service:
            qs = qs.filter(service=service)
        if tool:
            qs = qs.filter(tool_name=tool)
        if status:
            qs = qs.filter(status=status)
        if created_after is not None:
            qs = qs.filter(created_at__gte=created_after)
        if created_before is not None:
            qs = qs.filter(created_at__lt=created_before)
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
