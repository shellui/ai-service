"""Company delegation grants. One agent, many companies. Versions never go backwards."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from django.db import models
from django.utils import timezone

from apps.global_mcp.models import GlobalAgent, GlobalMcpApprovalRequest
from apps.global_mcp.saas_client import SaasError, request_json
from apps.global_mcp.tokens import REGIONAL_SERVICE_ORDER, issue_saas_api_token

REGIONAL_SERVICES = set(REGIONAL_SERVICE_ORDER)


class GlobalAgentCompanyGrant(models.Model):
    """Caps for one agent on one Shellui project. Region identity enforces them."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(GlobalAgent, on_delete=models.CASCADE, related_name='company_grants')
    global_company_id = models.UUIDField(db_index=True)
    regional_company_id = models.CharField(max_length=64, blank=True, default='')
    region_code = models.CharField(max_length=32, blank=True, default='')
    services = models.JSONField(default=list)
    max_access_mode = models.CharField(max_length=20, default=GlobalAgent.ACCESS_ASK)
    max_read_level = models.CharField(max_length=20, default=GlobalAgent.READ_SAFE)
    max_destructive = models.BooleanField(default=False)
    binding_version = models.PositiveIntegerField(default=1)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['agent', 'global_company_id'],
                name='global_grant_agent_company_uniq',
            ),
        ]

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


def active_grant(agent: GlobalAgent, company_id: str) -> GlobalAgentCompanyGrant | None:
    try:
        gid = uuid.UUID(str(company_id))
    except (TypeError, ValueError):
        return None
    return GlobalAgentCompanyGrant.objects.filter(
        agent=agent,
        global_company_id=gid,
        revoked_at__isnull=True,
    ).first()


def initial_binding_version(company: dict) -> int:
    raw = company.get('limits_version')
    try:
        current = int(raw or 0)
    except (TypeError, ValueError):
        current = 0
    if current < 0:
        current = 0
    return current + 1


def _services(raw) -> list[str]:
    if isinstance(raw, str):
        raw = raw.split()
    if not isinstance(raw, list):
        raw = []
    chosen = [item for item in REGIONAL_SERVICE_ORDER if item in set(raw)]
    if 'ai' not in chosen:
        chosen = ['ai', *chosen]
    return chosen


@dataclass
class GrantRequest:
    services: list[str]
    access_mode: str
    read_level: str
    destructive: bool


def normalize_grant_request(arguments: dict, agent: GlobalAgent) -> GrantRequest:
    services = _services(arguments.get('services') or ['ai', 'identity', 'storage', 'hosting', 'email'])
    access = str(arguments.get('access_mode') or agent.access_mode)
    if access not in {GlobalAgent.ACCESS_READ_ONLY, GlobalAgent.ACCESS_ASK, GlobalAgent.ACCESS_FULL}:
        access = agent.access_mode
    read_level = str(arguments.get('read_level') or agent.read_level)
    if read_level not in {GlobalAgent.READ_SAFE, GlobalAgent.READ_SENSITIVE}:
        read_level = agent.read_level
    destructive = arguments.get('allow_destructive')
    if destructive is None:
        destructive = agent.allow_destructive_without_asking
    return GrantRequest(services, access, read_level, bool(destructive))


def _rank_access(value: str) -> int:
    return {GlobalAgent.ACCESS_READ_ONLY: 0, GlobalAgent.ACCESS_ASK: 1, GlobalAgent.ACCESS_FULL: 2}.get(value, 1)


def _rank_read(value: str) -> int:
    return {GlobalAgent.READ_SAFE: 0, GlobalAgent.READ_SENSITIVE: 1}.get(value, 0)


def is_widening(grant: GlobalAgentCompanyGrant, requested: GrantRequest) -> bool:
    if set(requested.services) - set(grant.services or []):
        return True
    if _rank_access(requested.access_mode) > _rank_access(grant.max_access_mode):
        return True
    if _rank_read(requested.read_level) > _rank_read(grant.max_read_level):
        return True
    if requested.destructive and not grant.max_destructive:
        return True
    return False


def is_narrowing(grant: GlobalAgentCompanyGrant, requested: GrantRequest) -> bool:
    if set(grant.services or []) - set(requested.services):
        return True
    if _rank_access(requested.access_mode) < _rank_access(grant.max_access_mode):
        return True
    if _rank_read(requested.read_level) < _rank_read(grant.max_read_level):
        return True
    if grant.max_destructive and not requested.destructive:
        return True
    return False


def create_grant(
    agent: GlobalAgent,
    company: dict,
    requested: GrantRequest,
    *,
    binding_version: int | None = None,
) -> GlobalAgentCompanyGrant:
    version = binding_version if binding_version is not None else initial_binding_version(company)
    raw_region = company.get('region')
    if isinstance(raw_region, dict):
        region_code = str(raw_region.get('code') or company.get('region_code') or '')
    elif isinstance(raw_region, str) and raw_region.strip():
        region_code = raw_region.strip()
    else:
        region_code = str(company.get('region_code') or '')
    return GlobalAgentCompanyGrant.objects.create(
        agent=agent,
        global_company_id=uuid.UUID(str(company.get('id'))),
        regional_company_id=str(company.get('regional_company_id') or ''),
        region_code=region_code,
        services=requested.services,
        max_access_mode=requested.access_mode,
        max_read_level=requested.read_level,
        max_destructive=requested.destructive,
        binding_version=version,
    )


def narrow_grant(grant: GlobalAgentCompanyGrant, requested: GrantRequest) -> GlobalAgentCompanyGrant:
    grant.services = requested.services
    grant.max_access_mode = requested.access_mode
    grant.max_read_level = requested.read_level
    grant.max_destructive = requested.destructive
    grant.binding_version = int(grant.binding_version) + 1
    grant.save(
        update_fields=[
            'services',
            'max_access_mode',
            'max_read_level',
            'max_destructive',
            'binding_version',
            'updated_at',
        ]
    )
    fanout_revoke(grant)
    return grant


def revoke_grant(grant: GlobalAgentCompanyGrant) -> None:
    grant.revoked_at = timezone.now()
    grant.binding_version = int(grant.binding_version) + 1
    grant.save(update_fields=['revoked_at', 'binding_version', 'updated_at'])
    fanout_revoke(grant)


def maybe_setup_grant(agent: GlobalAgent, company: dict) -> GlobalAgentCompanyGrant | None:
    """The company this agent just created gets a grant without another approval link."""
    company_id = str(company.get('id') or '')
    if not company_id:
        return None
    if agent.setup_company_id and str(agent.setup_company_id) != company_id:
        return None
    existing = active_grant(agent, company_id)
    if existing is not None:
        return existing
    agent.setup_company_id = uuid.UUID(company_id)
    agent.save(update_fields=['setup_company_id', 'updated_at'])
    requested = GrantRequest(
        services=['ai', 'identity', 'storage', 'hosting', 'email'],
        access_mode=agent.access_mode,
        read_level=agent.read_level,
        destructive=bool(agent.allow_destructive_without_asking),
    )
    return create_grant(agent, company, requested)


def apply_grant_approval(approval: GlobalMcpApprovalRequest) -> GlobalAgentCompanyGrant | None:
    arguments = approval.arguments if isinstance(approval.arguments, dict) else {}
    company = arguments.get('company') if isinstance(arguments.get('company'), dict) else None
    if company is None:
        return None
    requested = normalize_grant_request(arguments, approval.agent)
    existing = active_grant(approval.agent, str(company.get('id') or ''))
    if existing is None:
        return create_grant(approval.agent, company, requested)
    if is_widening(existing, requested) or not is_narrowing(existing, requested):
        existing.services = requested.services
        existing.max_access_mode = requested.access_mode
        existing.max_read_level = requested.read_level
        existing.max_destructive = requested.destructive
        existing.binding_version = int(existing.binding_version) + 1
        existing.save(
            update_fields=[
                'services',
                'max_access_mode',
                'max_read_level',
                'max_destructive',
                'binding_version',
                'updated_at',
            ]
        )
        return existing
    return narrow_grant(existing, requested)


def fanout_revoke(grant: GlobalAgentCompanyGrant) -> None:
    """Ask saas to push the revoke. saas keeps the region provisioning channel."""
    try:
        token, _claims = issue_saas_api_token(grant.agent, purpose='global_agent_revoke')
        request_json(
            'POST',
            '/api/v1/internal/ai-global/revoke',
            token=token,
            body={
                'global_agent_id': str(grant.agent_id),
                'regional_company_id': grant.regional_company_id or None,
                'region_code': grant.region_code,
                'binding_version': int(grant.binding_version),
            },
        )
    except (SaasError, Exception):
        return


def builtin_tools() -> list[dict]:
    service_schema = {
        'type': 'array',
        'items': {'type': 'string', 'enum': list(REGIONAL_SERVICE_ORDER)},
        'description': 'Regional services. ai is always included.',
    }
    return [
        {
            'name': 'ai_grant_company_access',
            'description': (
                'Grant this agent access to one Shellui project. '
                'Only an owner can grant. A new or wider grant opens an approval link.'
            ),
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['company_id'],
                'properties': {
                    'company_id': {'type': 'string'},
                    'services': service_schema,
                    'access_mode': {'type': 'string', 'enum': ['read_only', 'ask', 'full']},
                    'read_level': {'type': 'string', 'enum': ['safe', 'sensitive']},
                    'allow_destructive': {'type': 'boolean'},
                },
            },
            'annotations': {'readOnlyHint': False, 'destructiveHint': False},
        },
        {
            'name': 'ai_revoke_company_access',
            'description': 'Revoke this agent on one Shellui project and bump the binding version.',
            'inputSchema': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['company_id'],
                'properties': {'company_id': {'type': 'string'}},
            },
            'annotations': {'readOnlyHint': False, 'destructiveHint': True},
        },
    ]
