"""List and revoke global MCP agents for the signed-in identity-global account."""

from __future__ import annotations

from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.global_mcp.grants import revoke_grant
from apps.global_mcp.identity_auth import GlobalIdentityAuthentication
from apps.global_mcp.models import GlobalAgent


def _iso(value) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def serialize_global_agent(agent: GlobalAgent) -> dict:
    client_id = None
    if agent.oauth_client_id and agent.oauth_client is not None:
        client_id = agent.oauth_client.client_id
    return {
        'id': str(agent.id),
        'kind': 'oauth' if client_id else 'personal',
        'name': agent.name,
        'access_mode': agent.access_mode,
        'read_level': agent.read_level,
        'allow_destructive_without_asking': bool(agent.allow_destructive_without_asking),
        'services_allowed': list(agent.services_allowed or []),
        'expires_at': None,
        'paused_at': _iso(agent.paused_at),
        'revoked_at': _iso(agent.revoked_at),
        'is_active': agent.is_active,
        'created_at': _iso(agent.created_at),
        'oauth_client_id': client_id,
        'personal_token_id': None,
    }


def agents_for_subject(sub: str):
    return (
        GlobalAgent.objects.filter(owner_sub=sub)
        .select_related('oauth_client')
        .order_by('-created_at')
    )


class GlobalAgentListView(APIView):
    authentication_classes = [GlobalIdentityAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        rows = [serialize_global_agent(agent) for agent in agents_for_subject(request.user.sub)]
        return Response({'agents': rows})


class GlobalAgentRevokeView(APIView):
    authentication_classes = [GlobalIdentityAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, agent_id):
        agent = agents_for_subject(request.user.sub).filter(pk=agent_id).first()
        if agent is None:
            return Response({'detail': 'Agent was not found.'}, status=404)
        if agent.revoked_at is None:
            agent.revoked_at = timezone.now()
            agent.save(update_fields=['revoked_at', 'updated_at'])
        for grant in agent.company_grants.filter(revoked_at__isnull=True):
            revoke_grant(grant)
        return Response({'agent': serialize_global_agent(agent)})
