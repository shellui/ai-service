from django.urls import path

from apps.connector.views import HealthView, McpServicesListView

urlpatterns = [
    path('health', HealthView.as_view(), name='ai-health'),
    path('mcp/services', McpServicesListView.as_view(), name='api_v1_mcp_services_list'),
]
