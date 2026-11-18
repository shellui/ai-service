"""Authenticate global MCP access tokens on JSON APIs."""

from __future__ import annotations

import jwt
from rest_framework import authentication, exceptions

from apps.global_mcp.mcp_views import authenticate
from apps.global_mcp.models import GlobalAgent


class GlobalAccessUser:
    def __init__(self, agent: GlobalAgent, claims: dict) -> None:
        self.agent = agent
        self.claims = claims
        self.sub = agent.owner_sub
        self.pk = agent.owner_sub
        self.is_authenticated = True
        self.is_staff = False

    def __str__(self) -> str:
        return self.sub


class GlobalMcpAccessAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        result = authenticate(request)
        if not isinstance(result, tuple):
            raise exceptions.AuthenticationFailed('The access token is not valid.')
        agent, claims = result
        return GlobalAccessUser(agent, claims), claims

    def authenticate_header(self, request):
        return 'Bearer'
