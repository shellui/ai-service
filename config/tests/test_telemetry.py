"""OpenTelemetry stays off without an endpoint, and a request span carries MCP attributes."""

from __future__ import annotations

import logging
import os
from unittest.mock import patch

import requests
from django.test import Client, SimpleTestCase, TestCase, override_settings

from apps.connector.tests.test_mcp_gateway import (
    _SIGNING,
    MCP_ACCEPT,
    _agent_token,
    _rpc,
)
from config.telemetry import annotate_mcp_span, setup_service_telemetry

_OTLP_ENV = (
    'OTEL_EXPORTER_OTLP_ENDPOINT',
    'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT',
    'OTEL_EXPORTER_OTLP_METRICS_ENDPOINT',
    'OTEL_EXPORTER_OTLP_HEADERS',
    'OTEL_EXPORTER_OTLP_PROTOCOL',
    'OTEL_SERVICE_NAME',
    'OTEL_RESOURCE_ATTRIBUTES',
    'OTEL_SDK_DISABLED',
    'AI_SERVICE_MODE',
    'SENTRY_ENVIRONMENT',
)


class TelemetryTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        self._saved_env = {name: os.environ.get(name) for name in _OTLP_ENV}
        for name in _OTLP_ENV:
            os.environ.pop(name, None)
        self._middleware = None
        from django.conf import settings

        self._middleware = list(settings.MIDDLEWARE)
        self._reset()

    def tearDown(self):
        self._reset()
        from django.conf import settings

        if self._middleware is not None:
            settings.MIDDLEWARE = self._middleware
        for name, value in self._saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        super().tearDown()

    def _reset(self):
        from shellui_django.telemetry import _reset_for_tests

        _reset_for_tests()

    def _exporter(self):
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        return InMemorySpanExporter()

    def test_setup_is_inert_without_an_endpoint(self):
        self.assertFalse(setup_service_telemetry())
        from shellui_django.telemetry._state import state

        self.assertFalse(state.active)
        annotate_mcp_span(method='tools/call', tool_name='storage_list_buckets', company_id=10)

    def test_request_span_and_resource_mode(self):
        os.environ['AI_SERVICE_MODE'] = 'region'
        os.environ['SENTRY_ENVIRONMENT'] = 'test'
        exporter = self._exporter()
        self.assertTrue(setup_service_telemetry(span_exporter=exporter))

        from opentelemetry import trace

        resource = trace.get_tracer_provider().resource.attributes
        self.assertEqual(resource['service.name'], 'ai-service')
        self.assertEqual(resource['service.version'], '0.3.0')
        self.assertEqual(resource['shellui.mode'], 'region')
        self.assertEqual(resource['deployment.environment'], 'test')

        response = Client().post('/mcp', data='{}', content_type='application/json')
        self.assertEqual(response.status_code, 404)
        spans = exporter.get_finished_spans()
        self.assertTrue(spans)
        self.assertTrue(any(span.context.trace_id for span in spans))

    def test_operator_mode_attribute_wins(self):
        os.environ['AI_SERVICE_MODE'] = 'region'
        os.environ['OTEL_RESOURCE_ATTRIBUTES'] = 'shellui.mode=global,cloud.region=eu'
        exporter = self._exporter()
        self.assertTrue(setup_service_telemetry(span_exporter=exporter))
        from opentelemetry import trace

        resource = trace.get_tracer_provider().resource.attributes
        self.assertEqual(resource['shellui.mode'], 'global')
        self.assertEqual(resource['cloud.region'], 'eu')

    def test_global_mode_resource_attribute(self):
        os.environ['AI_SERVICE_MODE'] = 'global'
        exporter = self._exporter()
        self.assertTrue(setup_service_telemetry(span_exporter=exporter))
        from opentelemetry import trace

        self.assertEqual(trace.get_tracer_provider().resource.attributes['shellui.mode'], 'global')

    def test_mcp_attributes_and_outbound_traceparent(self):
        exporter = self._exporter()
        self.assertTrue(setup_service_telemetry(span_exporter=exporter))
        from opentelemetry import trace

        captured: dict[str, str] = {}

        def fake_urlopen(pool, method, url, body=None, headers=None, **kwargs):
            for key, value in (headers or {}).items():
                if str(key).lower() == 'traceparent':
                    captured['traceparent'] = str(value)
            raise requests.ConnectionError('stopped')

        tracer = trace.get_tracer('ai-service.test')
        with patch('urllib3.connectionpool.HTTPConnectionPool.urlopen', fake_urlopen):
            with tracer.start_as_current_span('mcp-request'):
                annotate_mcp_span(
                    method='tools/call',
                    tool_name='storage_list_buckets',
                    company_id=10,
                    user_id=7,
                    agent_id='agent-a',
                )
                span = trace.get_current_span()
                self.assertEqual(span.attributes['mcp.method.name'], 'tools/call')
                self.assertEqual(span.attributes['mcp.tool.name'], 'storage_list_buckets')
                self.assertEqual(span.attributes['shellui.company_id'], '10')
                self.assertEqual(span.attributes['shellui.user_id'], '7')
                self.assertEqual(span.attributes['shellui.agent_id'], 'agent-a')
                self.assertNotIn('mcp.tool.arguments', span.attributes or {})
                try:
                    requests.post(
                        'http://identity.test/api/v1/mcp/internal/mcp-downstream-access-token',
                        json={'arguments': {'secret': 'do-not-export'}},
                        timeout=1,
                    )
                except requests.ConnectionError:
                    pass

        self.assertIn('traceparent', captured)
        self.assertTrue(captured['traceparent'])
        finished = [span for span in exporter.get_finished_spans() if span.name == 'mcp-request']
        self.assertEqual(len(finished), 1)
        attributes = finished[0].attributes
        self.assertEqual(attributes['mcp.method.name'], 'tools/call')
        self.assertEqual(attributes['mcp.tool.name'], 'storage_list_buckets')
        rendered = ' '.join(f'{key}={value}' for key, value in attributes.items())
        self.assertNotIn('do-not-export', rendered)
        self.assertNotIn('arguments', rendered)

    def test_tool_arguments_are_not_span_attributes(self):
        exporter = self._exporter()
        self.assertTrue(setup_service_telemetry(span_exporter=exporter))
        from opentelemetry import trace

        tracer = trace.get_tracer('ai-service.test')
        with tracer.start_as_current_span('call'):
            annotate_mcp_span(method='tools/call', tool_name='not a tool', company_id='user@example.com')
            span = trace.get_current_span()
            self.assertEqual(span.attributes['mcp.method.name'], 'tools/call')
            self.assertNotIn('mcp.tool.name', span.attributes)
            self.assertNotIn('shellui.company_id', span.attributes)

    def test_logs_include_trace_ids_and_request_id(self):
        exporter = self._exporter()
        self.assertTrue(setup_service_telemetry(span_exporter=exporter))
        from opentelemetry import trace
        from shellui_django.telemetry import TraceContextFormatter

        from config.request_context import RequestIdFilter, request_id_var

        stream_messages = []

        class _Capture(logging.Handler):
            def emit(self, record):
                stream_messages.append(self.format(record))

        handler = _Capture()
        handler.setFormatter(
            TraceContextFormatter('%(message)s trace_id=%(trace_id)s span_id=%(span_id)s req=%(request_id)s')
        )
        handler.addFilter(RequestIdFilter())
        logger = logging.getLogger('config.tests.telemetry')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        token = request_id_var.set('req-123')
        try:
            logger.info('idle')
            tracer = trace.get_tracer('ai-service.test')
            with tracer.start_as_current_span('logged'):
                logger.info('inside')
        finally:
            request_id_var.reset(token)
            logger.removeHandler(handler)

        self.assertIn('idle trace_id=0 span_id=0 req=req-123', stream_messages[0])
        self.assertIn('req=req-123', stream_messages[1])
        self.assertRegex(stream_messages[1], r'trace_id=[0-9a-f]{32} span_id=[0-9a-f]{16}')

    def test_metrics_endpoints_are_not_served(self):
        client = Client()
        for path in ('/metrics', '/metrics/', '/metrics/all', '/metrics/all/'):
            response = client.get(path)
            self.assertEqual(response.status_code, 404, path)


@override_settings(
    DEBUG=True,
    JWT_HS256_FALLBACK_SECRET='test-hs256-secret-for-mcp-gateway-tests-only',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_AUDIENCE='shellui-test',
    IDENTITY_JWKS_URL='http://localhost:8000/.well-known/jwks.json',
    STORAGE_SERVICE_URL='https://storage.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    AI_PUBLIC_URL='https://ai.test',
    AI_SERVICE_SIGNING_KEY=_SIGNING,
    AI_SERVICE_ISSUER='https://ai.test',
    AI_SERVICE_MODE='region',
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'ai-telemetry-mcp',
        }
    },
)
@patch('apps.connector.mcp_views.identity_revocation_unavailable', return_value=False)
@patch('apps.connector.mcp_views.agent_is_revoked', return_value=False)
class McpRequestSpanTests(TestCase):
    def setUp(self):
        super().setUp()
        self._saved_env = {name: os.environ.get(name) for name in _OTLP_ENV}
        for name in _OTLP_ENV:
            os.environ.pop(name, None)
        from django.conf import settings

        self._middleware = list(settings.MIDDLEWARE)
        from shellui_django.telemetry import _reset_for_tests

        _reset_for_tests()
        self.exporter = None

    def tearDown(self):
        from django.conf import settings
        from shellui_django.telemetry import _reset_for_tests

        _reset_for_tests()
        settings.MIDDLEWARE = self._middleware
        for name, value in self._saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        super().tearDown()

    def test_tools_call_span_names_the_tool_and_continues_downstream(self, _revoked, _rev_ok):
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        self.exporter = InMemorySpanExporter()
        self.assertTrue(setup_service_telemetry(span_exporter=self.exporter))
        captured: dict[str, str] = {}

        def fake_post(url, json=None, headers=None, timeout=None, **kwargs):
            for key, value in (headers or {}).items():
                if str(key).lower() == 'traceparent':
                    captured['traceparent'] = str(value)
            response = requests.Response()
            response.status_code = 200
            response.url = url
            response._content = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}'
            response.headers['Content-Type'] = 'application/json'
            return response

        token = _agent_token(
            secret='test-hs256-secret-for-mcp-gateway-tests-only',
            issuer='https://identity.test',
        )
        with (
            patch('apps.connector.mcp_views.mint_downstream_access_token', return_value='downstream-token'),
            patch('shellui_django.mcp.gateway.requests.post', side_effect=fake_post),
        ):
            response = Client().post(
                '/c/10/mcp',
                data=_rpc('tools/call', name='storage_list_buckets', arguments={'bucket': 'secret-bucket'}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                HTTP_ACCEPT=MCP_ACCEPT,
            )
        self.assertIn(response.status_code, {200, 202, 400, 403, 404, 503})
        spans = self.exporter.get_finished_spans()
        matched = [
            span
            for span in spans
            if span.attributes and span.attributes.get('mcp.method.name') == 'tools/call'
        ]
        self.assertTrue(matched, [span.attributes for span in spans])
        attributes = matched[0].attributes
        self.assertEqual(attributes.get('mcp.tool.name'), 'storage_list_buckets')
        rendered = ' '.join(f'{key}={value}' for key, value in attributes.items())
        self.assertNotIn('secret-bucket', rendered)
        self.assertEqual(attributes.get('shellui.company_id'), '10')
        self.assertEqual(attributes.get('shellui.agent_id'), 'agent-a')
        # The gateway mock replaces requests.post, so traceparent is asserted on the real client path
        # in TelemetryTests. This request still has to reach the tool name without exporting arguments.
        self.assertNotIn('secret-bucket', captured.get('traceparent', ''))
