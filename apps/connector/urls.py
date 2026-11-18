from django.urls import path

from apps.connector.call_log_views import McpCallLogListView, PersonalAgentCallLogListView
from apps.connector.views import HealthView, McpServicesListView

urlpatterns = [
    path('health', HealthView.as_view(), name='ai-health'),
    path('mcp/services', McpServicesListView.as_view(), name='api_v1_mcp_services_list'),
    path('mcp/call-logs', McpCallLogListView.as_view(), name='ai_v1_mcp_call_logs_list'),
    path(
        'mcp/personal/agents/<str:agent_id>/call-logs',
        PersonalAgentCallLogListView.as_view(),
        name='ai_v1_mcp_personal_agent_call_logs_list',
    ),
]
