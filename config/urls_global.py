"""Global URL conf for tests. Production uses config.urls, which follows AI_SERVICE_MODE."""

from config.urlpatterns import global_urlpatterns

urlpatterns = global_urlpatterns()

handler400 = 'config.errors.bad_request'
handler403 = 'config.errors.permission_denied'
handler404 = 'config.errors.page_not_found'
handler500 = 'config.errors.server_error'
