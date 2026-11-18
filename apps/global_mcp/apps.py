from django.apps import AppConfig


class GlobalMcpConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.global_mcp'
    verbose_name = 'Global MCP'

    def ready(self) -> None:
        from . import grants  # noqa: F401
