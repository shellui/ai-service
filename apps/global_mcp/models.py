"""Global MCP agent, OAuth, and approval rows. Companies stay in saas-service."""

from __future__ import annotations

import uuid

from django.db import models


class McpOAuthClient(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client_id = models.CharField(max_length=64, unique=True, db_index=True)
    client_name = models.CharField(max_length=255, blank=True)
    redirect_uris = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class GlobalAgent(models.Model):
    ACCESS_READ_ONLY = 'read_only'
    ACCESS_ASK = 'ask'
    ACCESS_FULL = 'full'
    ACCESS_CHOICES = [
        (ACCESS_READ_ONLY, 'Read only'),
        (ACCESS_ASK, 'Ask before changes'),
        (ACCESS_FULL, 'Full access'),
    ]

    READ_SAFE = 'safe'
    READ_SENSITIVE = 'sensitive'
    READ_CHOICES = [
        (READ_SAFE, 'Safe reads'),
        (READ_SENSITIVE, 'Sensitive data'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    owner_sub = models.CharField(max_length=255, db_index=True)
    owner_email = models.EmailField()
    owner_name = models.CharField(max_length=255, blank=True)
    oauth_client = models.ForeignKey(
        McpOAuthClient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='agents',
    )
    access_mode = models.CharField(max_length=20, choices=ACCESS_CHOICES, default=ACCESS_ASK)
    allow_destructive_without_asking = models.BooleanField(default=False)
    read_level = models.CharField(max_length=20, choices=READ_CHOICES, default=READ_SAFE)
    services_allowed = models.JSONField(default=list)
    setup_flow = models.BooleanField(default=False)
    setup_expires_at = models.DateTimeField(null=True, blank=True)
    setup_company_id = models.UUIDField(null=True, blank=True)
    paused_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.paused_at is None


class McpAuthorizationRequest(models.Model):
    """Browser authorize request, stored until the consent page finishes."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.ForeignKey(McpOAuthClient, on_delete=models.CASCADE)
    redirect_uri = models.CharField(max_length=500)
    state = models.CharField(max_length=500, blank=True)
    code_challenge = models.CharField(max_length=128)
    resource = models.CharField(max_length=500, blank=True)
    scope = models.CharField(max_length=200, blank=True, default='mcp')
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class OidcTransaction(models.Model):
    """PKCE state for the confidential login at identity-global."""

    state = models.CharField(max_length=128, unique=True, db_index=True)
    nonce = models.CharField(max_length=128)
    code_verifier = models.CharField(max_length=128)
    authorization_request = models.ForeignKey(McpAuthorizationRequest, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class McpAuthorizationCode(models.Model):
    code_hash = models.CharField(max_length=64, unique=True, db_index=True)
    client = models.ForeignKey(McpOAuthClient, on_delete=models.CASCADE)
    owner_sub = models.CharField(max_length=255)
    owner_email = models.EmailField()
    owner_name = models.CharField(max_length=255, blank=True)
    owner_claims = models.JSONField(default=dict)
    agent = models.ForeignKey(GlobalAgent, on_delete=models.CASCADE)
    redirect_uri = models.CharField(max_length=500)
    code_challenge = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    redeemed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class GlobalRefreshToken(models.Model):
    """Rotating refresh token. Reuse of a rotated token revokes the family."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(GlobalAgent, on_delete=models.CASCADE, related_name='refresh_tokens')
    family_id = models.UUIDField(db_index=True)
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    rotated_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class GlobalMcpApprovalRequest(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_EXPIRED = 'expired'
    STATUS_EXECUTED = 'executed'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_EXPIRED, 'Expired'),
        (STATUS_EXECUTED, 'Executed'),
    ]
    KIND_TOOL = 'tool'
    KIND_GRANT = 'grant'
    KIND_CHOICES = [
        (KIND_TOOL, 'Tool'),
        (KIND_GRANT, 'Grant'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(GlobalAgent, on_delete=models.CASCADE, related_name='approvals')
    owner_sub = models.CharField(max_length=255, db_index=True)
    kind = models.CharField(max_length=16, choices=KIND_CHOICES, default=KIND_TOOL)
    service = models.CharField(max_length=32, default='saas')
    action = models.CharField(max_length=255)
    arguments_hash = models.CharField(max_length=64, db_index=True)
    arguments_redacted = models.JSONField(default=dict)
    arguments = models.JSONField(default=dict)
    is_destructive = models.BooleanField(default=False)
    channel = models.CharField(max_length=8, default='form')
    short_action_summary = models.CharField(max_length=500, blank=True)
    method = models.CharField(max_length=16, blank=True)
    path = models.CharField(max_length=500, blank=True)
    global_company_id = models.UUIDField(null=True, blank=True, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    expires_at = models.DateTimeField(db_index=True)
    human_decided_at = models.DateTimeField(null=True, blank=True)
    decided_by_sub = models.CharField(max_length=255, blank=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class GlobalMcpApprovalDecisionAudit(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    approval = models.ForeignKey(GlobalMcpApprovalRequest, on_delete=models.CASCADE, related_name='decision_audits')
    event = models.CharField(max_length=16, db_index=True)
    actor_sub = models.CharField(max_length=255, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)


class GlobalMcpApprovalSessionGrant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent_id = models.UUIDField(db_index=True)
    service = models.CharField(max_length=32, default='saas')
    action = models.CharField(max_length=255)
    arguments_hash = models.CharField(max_length=64)
    connection_id = models.CharField(max_length=128, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class GlobalAgentTokenAudit(models.Model):
    EVENT_ACCESS_MINT = 'access_mint'
    EVENT_CODE_EXCHANGE = 'authorization_code_exchange'
    EVENT_REFRESH = 'refresh'
    EVENT_SUBJECT = 'subject_token'
    EVENT_SAAS = 'saas_api_token'
    EVENT_CHOICES = [
        (EVENT_ACCESS_MINT, 'MCP access token'),
        (EVENT_CODE_EXCHANGE, 'Authorization code exchange'),
        (EVENT_REFRESH, 'Refresh'),
        (EVENT_SUBJECT, 'Regional subject token'),
        (EVENT_SAAS, 'SaaS API token'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=40, choices=EVENT_CHOICES, db_index=True)
    global_agent = models.ForeignKey(
        GlobalAgent,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='token_audits',
    )
    owner_sub = models.CharField(max_length=255, db_index=True)
    global_company_id = models.CharField(max_length=64, blank=True)
    jti = models.CharField(max_length=64, db_index=True)
    exp = models.DateTimeField()
    oauth_client_id = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner_sub', 'created_at'], name='gmaudit_owner_created_idx'),
        ]
