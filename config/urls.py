"""URL configuration for ai-service. The mode is chosen once, at boot."""

from django.conf import settings

from .urlpatterns import global_urlpatterns, region_urlpatterns

urlpatterns = global_urlpatterns() if getattr(settings, 'AI_SERVICE_MODE', 'region') == 'global' else region_urlpatterns()

handler400 = 'config.errors.bad_request'
handler403 = 'config.errors.permission_denied'
handler404 = 'config.errors.page_not_found'
handler500 = 'config.errors.server_error'
