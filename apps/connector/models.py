"""Local MCP tool-call log. ai-service is the source of truth for gateway calls."""

from django.db import models


class McpCallLog(models.Model):
    """One row per gateway ``tools/call``. Arguments are redacted before insert."""

    STATUS_ALLOWED = 'allowed'
    STATUS_DENIED = 'denied'
    STATUS_WAITING = 'waiting_approval'
    STATUS_FAILED = 'failed'
    STATUS_ERROR = 'error'
    STATUSES = (
        (STATUS_ALLOWED, 'Allowed'),
        (STATUS_DENIED, 'Denied'),
        (STATUS_WAITING, 'Waiting approval'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_ERROR, 'Error'),
    )

    CHANNEL_FORM = 'form'
    CHANNEL_LINK = 'link'
    CHANNEL_NONE = 'none'
    CHANNELS = (
        (CHANNEL_FORM, 'Form'),
        (CHANNEL_LINK, 'Link'),
        (CHANNEL_NONE, 'None'),
    )

    company_id = models.PositiveIntegerField()
    agent_id = models.CharField(max_length=128, blank=True, default='')
    agent_name = models.CharField(max_length=200, blank=True, default='')
    client_id = models.CharField(max_length=128, blank=True, default='')
    client_name = models.CharField(max_length=120, blank=True, default='')
    token_kind = models.CharField(max_length=32, blank=True, default='')
    user_id = models.PositiveIntegerField(null=True, blank=True)
    user_email = models.CharField(max_length=254, blank=True, default='')
    service = models.CharField(max_length=32, blank=True, default='')
    tool_name = models.CharField(max_length=255, blank=True, default='')
    wrapper_tool = models.CharField(max_length=64, blank=True, default='')
    arguments_redacted = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=32, choices=STATUSES)
    status_code = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=64, blank=True, default='')
    error_message = models.CharField(max_length=500, blank=True, default='')
    duration_ms = models.PositiveIntegerField(default=0)
    approval_id = models.CharField(max_length=64, blank=True, default='')
    approval_channel = models.CharField(max_length=8, choices=CHANNELS, default=CHANNEL_NONE)
    approval_outcome = models.CharField(max_length=32, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['company_id', 'created_at'], name='mcpcall_co_created_idx'),
            models.Index(fields=['company_id', 'agent_id'], name='mcpcall_co_agent_idx'),
        ]

    def __str__(self) -> str:
        return f'{self.company_id}:{self.tool_name}:{self.status}'
