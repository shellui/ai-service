"""SaaS tool calls stay on the configured base and the OpenAPI path template."""

from __future__ import annotations

from unittest.mock import patch
from urllib.parse import urlsplit

from django.test import SimpleTestCase, override_settings

from apps.global_mcp.openapi_tools import call_saas_tool
from apps.global_mcp.saas_client import SaasError, request_json

BASE = 'https://saas.example'
SETTINGS = dict(SAAS_SERVICE_URL=BASE, SAAS_SERVICE_INTERNAL_URL=BASE)


def _response(payload=None):
    class Response:
        status_code = 200
        text = ''

        def json(self):
            return {} if payload is None else payload

    return Response()


@override_settings(**SETTINGS)
class SaasUrlTests(SimpleTestCase):
    def test_path_param_dotdot_stays_on_the_template(self):
        tool = {
            'name': 'saas_get_companies',
            '_meta': {'method': 'GET', 'path': '/api/v1/companies/{company_id}', 'read_only': True},
        }
        with patch('apps.global_mcp.saas_client.requests.request') as request:
            request.return_value = _response()
            status, _payload = call_saas_tool(tool, {'company_id': '../admin'}, token='t')
        self.assertEqual(status, 200)
        url = request.call_args.args[1]
        parts = urlsplit(url)
        self.assertEqual(parts.scheme, 'https')
        self.assertEqual(parts.hostname, 'saas.example')
        self.assertEqual(parts.path, '/api/v1/companies/%2E%2E%2Fadmin')

    def test_absolute_url_param_does_not_leave_the_base(self):
        tool = {
            'name': 'saas_get_resource',
            '_meta': {'method': 'GET', 'path': '/{company_id}', 'read_only': True},
        }
        with patch('apps.global_mcp.saas_client.requests.request') as request:
            request.return_value = _response()
            call_saas_tool(tool, {'company_id': 'https://evil.example/steal'}, token='t')
        url = request.call_args.args[1]
        parts = urlsplit(url)
        self.assertEqual(parts.hostname, 'saas.example')
        self.assertNotIn('evil.example', parts.netloc)
        self.assertTrue(parts.path.startswith('/'))
        self.assertNotIn('://', parts.path)

    def test_template_dotdot_is_refused(self):
        tool = {
            'name': 'saas_get_secret',
            '_meta': {'method': 'GET', 'path': '/api/v1/../../secret', 'read_only': True},
        }
        with patch('apps.global_mcp.saas_client.requests.request') as request:
            with self.assertRaises(SaasError):
                call_saas_tool(tool, {}, token='t')
        request.assert_not_called()

    def test_request_json_rejects_an_absolute_url(self):
        with patch('apps.global_mcp.saas_client.requests.request') as request:
            with self.assertRaises(SaasError):
                request_json('GET', 'https://evil.example/collect', token='t')
        request.assert_not_called()

    def test_request_json_never_follows_a_redirect(self):
        redirected = _response({'detail': 'moved'})
        redirected.status_code = 302
        with patch('apps.global_mcp.saas_client.requests.request', return_value=redirected) as request:
            status, _payload = request_json('GET', '/api/v1/me', token='t')
        self.assertEqual(status, 302)
        self.assertIs(request.call_args.kwargs['allow_redirects'], False)

    def test_request_json_rejects_dotdot_that_leaves_the_base(self):
        with patch('apps.global_mcp.saas_client.requests.request') as request:
            with self.assertRaises(SaasError):
                request_json('GET', '/api/v1/../../secret', token='t')
        request.assert_not_called()

    @override_settings(SAAS_SERVICE_URL='https://saas.example/api', SAAS_SERVICE_INTERNAL_URL='https://saas.example/api')
    def test_dotdot_cannot_leave_a_base_path(self):
        with patch('apps.global_mcp.saas_client.requests.request') as request:
            with self.assertRaises(SaasError):
                request_json('GET', '/../secret', token='t')
        request.assert_not_called()

    def test_ordinary_path_stays_on_the_base(self):
        with patch('apps.global_mcp.saas_client.requests.request') as request:
            request.return_value = _response({'id': 'abc'})
            status, payload = request_json('GET', '/api/v1/companies/abc', token='t')
        self.assertEqual(status, 200)
        self.assertEqual(payload['id'], 'abc')
        self.assertEqual(request.call_args.args[1], 'https://saas.example/api/v1/companies/abc')
        self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer t')
