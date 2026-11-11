"""Delete MCP call logs older than the retention window."""

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.connector.models import McpCallLog


class Command(BaseCommand):
    help = 'Delete MCP call logs older than MCP_CALL_LOG_RETENTION_DAYS (default 90).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=None,
            help='Override MCP_CALL_LOG_RETENTION_DAYS. Must be at least 1.',
        )

    def handle(self, *args, **options):
        days = options.get('days')
        if days is None:
            days = int(getattr(settings, 'MCP_CALL_LOG_RETENTION_DAYS', 90))
        if days < 1:
            raise CommandError('days must be at least 1')
        cutoff = timezone.now() - timedelta(days=days)
        deleted, _detail = McpCallLog.objects.filter(created_at__lt=cutoff).delete()
        self.stdout.write(f'pruned {deleted} mcp call log rows older than {days} days')
