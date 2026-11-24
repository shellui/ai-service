"""OpenTelemetry setup for ai-service.

Export stays off until an OTLP endpoint is configured. Importing this module
does not import the OpenTelemetry SDK.
"""

from __future__ import annotations

import logging
import os
import re
import tomllib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MODE_ATTRIBUTE = 'shellui.mode'
_MODES = frozenset({'region', 'global'})
_MCP_METHOD = re.compile(r'^[A-Za-z][A-Za-z0-9._/-]{0,127}$')
_MCP_TOOL = re.compile(r'^[A-Za-z0-9_.:/-]{1,256}$')
_OPAQUE_ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
_BASE_DIR = Path(__file__).resolve().parent.parent


def service_mode() -> str:
    """Boot mode from ``AI_SERVICE_MODE``. Invalid values stay ``region`` until settings refuse to start."""
    mode = os.getenv('AI_SERVICE_MODE', 'region').strip().lower() or 'region'
    if mode not in _MODES:
        return 'region'
    return mode


def _package_version() -> str:
    pyproject = _BASE_DIR / 'pyproject.toml'
    with pyproject.open('rb') as fh:
        data = tomllib.load(fh)
    return str(data.get('project', {}).get('version') or '').strip()


def _deployment_environment() -> str:
    explicit = os.getenv('SENTRY_ENVIRONMENT', '').strip()
    if explicit:
        return explicit
    debug = os.getenv('DEBUG', 'false').strip().lower() in {'1', 'true', 'yes', 'on'}
    return 'development' if debug else 'production'


def _resource_keys(raw: str) -> set[str]:
    keys: set[str] = set()
    for item in raw.split(','):
        if '=' not in item:
            continue
        key = item.split('=', 1)[0].strip()
        if key:
            keys.add(key)
    return keys


def _merge_mode_attribute(mode: str) -> None:
    """Add ``shellui.mode`` unless the operator already set it."""
    raw = os.getenv('OTEL_RESOURCE_ATTRIBUTES', '')
    if _MODE_ATTRIBUTE in _resource_keys(raw):
        return
    piece = f'{_MODE_ATTRIBUTE}={mode}'
    os.environ['OTEL_RESOURCE_ATTRIBUTES'] = f'{raw},{piece}' if raw.strip() else piece


def _otel_environment() -> dict[str, str]:
    return {
        'endpoint': os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', '').strip(),
        'headers': os.getenv('OTEL_EXPORTER_OTLP_HEADERS', '').strip(),
        'protocol': os.getenv('OTEL_EXPORTER_OTLP_PROTOCOL', '').strip(),
        'service_name': os.getenv('OTEL_SERVICE_NAME', '').strip(),
        'resource_attributes': os.getenv('OTEL_RESOURCE_ATTRIBUTES', '').strip(),
    }


def setup_service_telemetry(**kwargs: Any) -> bool:
    """Configure traces and metrics. Safe to call again in this process and after fork."""
    mode = service_mode()
    _merge_mode_attribute(mode)
    otel = _otel_environment()
    if not otel['protocol']:
        os.environ.setdefault('OTEL_EXPORTER_OTLP_PROTOCOL', 'http/protobuf')
    elif otel['protocol'] != 'http/protobuf':
        logger.warning(
            'OTEL_EXPORTER_OTLP_PROTOCOL=%s is not supported. Use http/protobuf.',
            otel['protocol'],
        )
    if otel['headers'] and not otel['endpoint'] and not kwargs:
        logger.warning('OTEL_EXPORTER_OTLP_HEADERS is set but OTEL_EXPORTER_OTLP_ENDPOINT is empty.')

    from shellui_django.telemetry import setup_telemetry

    return setup_telemetry(
        otel['service_name'] or 'ai-service',
        service_version=_package_version() or None,
        environment=_deployment_environment(),
        **kwargs,
    )


def _opaque(value: object) -> str | int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text or '@' in text or not _OPAQUE_ID.fullmatch(text):
        return None
    return text


def annotate_mcp_span(
    *,
    method: str = '',
    tool_name: str = '',
    company_id: object = None,
    user_id: object = None,
    agent_id: object = None,
) -> None:
    """Record the MCP method and tool name on the current span.

    Tool arguments and results are never copied onto the span.
    """
    from shellui_django.telemetry._state import state

    if not state.active:
        return

    from opentelemetry import trace
    from shellui_django.telemetry import set_shellui_attributes

    span = trace.get_current_span()
    if span.is_recording():
        method_text = method.strip() if isinstance(method, str) else ''
        if _MCP_METHOD.fullmatch(method_text):
            span.set_attribute('mcp.method.name', method_text)
        tool_text = tool_name.strip() if isinstance(tool_name, str) else ''
        if tool_text and _MCP_TOOL.fullmatch(tool_text):
            span.set_attribute('mcp.tool.name', tool_text)

    attributes: dict[str, str | int] = {}
    agent = _opaque(agent_id)
    if agent is not None:
        attributes['agent_id'] = agent
    set_shellui_attributes(
        company_id=_opaque(company_id),
        user_id=_opaque(user_id),
        attributes=attributes or None,
    )
