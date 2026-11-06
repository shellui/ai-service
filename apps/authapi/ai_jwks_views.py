"""Public JWKS for ai-service downstream-token delegation JWTs."""

from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from apps.authapi.ai_service_jwks import build_jwks_document


@method_decorator(cache_page(60 * 15), name='dispatch')
class AiServiceJwksView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['.well-known'],
        summary='JSON Web Key Set (JWKS)',
        responses={200: OpenApiResponse(description='Public RS256 key for ai-service delegation JWTs.')},
    )
    def get(self, request):
        signing_key = getattr(settings, 'AI_SERVICE_SIGNING_KEY', None)
        if signing_key is None:
            return JsonResponse({'keys': []})
        document = build_jwks_document(signing_key)
        response = JsonResponse(document)
        response['Cache-Control'] = 'public, max-age=900'
        return response
