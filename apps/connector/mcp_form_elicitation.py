"""Classic MCP form elicitation (protocol 2025-06-18).

The negotiated revision tells us how a client can answer. ``2025-06-18`` expects a
server request ``elicitation/create`` on the Streamable HTTP session, not a tool
result with ``resultType: input_required`` (that shape is ``2026-07-28``, which this
gateway does not negotiate). ``input_required`` is only built when a future session
actually negotiates that revision.

The POST response is ``text/event-stream``: the elicitation request, then the
original ``tools/call`` result after the client POSTs its JSON-RPC response, or
after the wait ends. The fallback result is the human approval link.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from typing import Any

from django.core.cache import cache
from django.http import HttpRequest, StreamingHttpResponse

FORM_ELICITATION_PROTOCOL = '2025-06-18'
URL_ELICITATION_PROTOCOL = '2025-11-25'
INPUT_REQUIRED_PROTOCOL = '2026-07-28'
# Classic ``elicitation/create`` on the tools/call SSE stream (form and/or url).
SSE_ELICITATION_PROTOCOLS = frozenset({FORM_ELICITATION_PROTOCOL, URL_ELICITATION_PROTOCOL})
_OPEN_PREFIX = 'mcp_gateway:elicit-open:'
_RESULT_PREFIX = 'mcp_gateway:elicit-result:'
_TTL_SECONDS = 120


def form_delivery(*, protocol_version: str, form_declared: bool, accepts_sse: bool, wait_seconds: float) -> str:
    """``sse``, ``input_required``, or ``link``."""
    if not form_declared or wait_seconds <= 0:
        return 'link'
    version = str(protocol_version or '').strip()
    if version == INPUT_REQUIRED_PROTOCOL:
        return 'input_required'
    if version in SSE_ELICITATION_PROTOCOLS and accepts_sse:
        return 'sse'
    return 'link'


def can_stream_elicitation(*, protocol_version: str, accepts_sse: bool, wait_seconds: float | None = None) -> bool:
    """Whether this session can carry ``elicitation/create`` on a tools/call SSE response."""
    seconds = elicitation_wait_seconds() if wait_seconds is None else float(wait_seconds)
    if seconds <= 0 or not accepts_sse:
        return False
    return str(protocol_version or '').strip() in SSE_ELICITATION_PROTOCOLS


def request_accepts_sse(request: HttpRequest) -> bool:
    accept = str(request.headers.get('Accept') or '')
    return 'text/event-stream' in accept.lower()


def elicitation_wait_seconds() -> float:
    from django.conf import settings

    raw = getattr(settings, 'MCP_APPROVAL_FORM_ELICITATION_WAIT_SECONDS', 90)
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return 90.0


def classic_form_params(*, message: str) -> dict[str, Any]:
    """``elicitation/create`` params for protocol 2025-06-18 (mode defaults to form)."""
    return {
        'mode': 'form',
        'message': message,
        'requestedSchema': {
            'type': 'object',
            'properties': {
                'decision': {
                    'type': 'string',
                    'title': 'Decision',
                    'enum': ['approve', 'deny'],
                    'enumNames': ['Approve', 'Deny'],
                }
            },
            'required': ['decision'],
        },
    }


def classic_url_params(*, message: str, url: str) -> dict[str, Any]:
    """``elicitation/create`` with ``mode: url`` so the client can open the page."""
    from secrets import token_urlsafe

    return {
        'mode': 'url',
        'elicitationId': token_urlsafe(16),
        'url': url,
        'message': message,
    }


def remember_open_elicitation(session_id: str, rpc_id: str) -> None:
    cache.set(f'{_OPEN_PREFIX}{session_id}', str(rpc_id), _TTL_SECONDS)


def open_elicitation_id(session_id: str) -> str:
    return str(cache.get(f'{_OPEN_PREFIX}{session_id}') or '')


def store_elicitation_result(session_id: str, rpc_id: str, result: dict[str, Any]) -> bool:
    """Save a client JSON-RPC result for an elicitation this session opened."""
    expected = open_elicitation_id(session_id)
    if not expected or str(rpc_id) != expected:
        return False
    cache.set(f'{_RESULT_PREFIX}{session_id}:{rpc_id}', result, _TTL_SECONDS)
    return True


def _take_result(session_id: str, rpc_id: str) -> dict[str, Any] | None:
    key = f'{_RESULT_PREFIX}{session_id}:{rpc_id}'
    value = cache.get(key)
    if isinstance(value, dict):
        cache.delete(key)
        return value
    return None


def wait_for_elicitation_result(
    session_id: str,
    rpc_id: str,
    *,
    timeout_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any] | None:
    timeout = max(0.0, float(timeout_seconds))
    deadline = time.monotonic() + timeout
    while True:
        found = _take_result(session_id, rpc_id)
        if found is not None:
            return found
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sleep(min(0.05, remaining))


def wait_for_link_page_approval(
    *,
    approval_payload: dict[str, Any],
    session_id: str = '',
    rpc_id: str = '',
    timeout_seconds: float,
    interval_seconds: float = 0.5,
    sleep: Callable[[float], None] = time.sleep,
    approval_state: Callable[[dict[str, Any]], str | None] | None = None,
    wait_decision: Callable[..., str | None] | None = None,
) -> str | None:
    """Wait until the browser page decides, or the timeout elapses.

    Uses Redis/local wake (Identity POSTs decide → ai publish). One Identity
    ``approval_state`` read at start and again on timeout as fallback. Client
    elicitation answers (Open / dismiss / decline) are drained and ignored —
    only the identity approval page can approve or deny a link-channel row.

    ``interval_seconds`` and ``sleep`` are retained for callers/tests; the happy
    path no longer polls Identity on that interval.
    """
    from apps.connector import mcp_approvals as approvals
    from apps.connector.mcp_approval_events import wait_approval_decision

    _ = (interval_seconds, sleep)  # wake path; Identity is not polled on an interval
    state_fn = approval_state or approvals.approval_state
    wait_fn = wait_decision or wait_approval_decision
    timeout = max(0.0, float(timeout_seconds))

    def drain() -> None:
        if session_id and rpc_id:
            _take_result(session_id, rpc_id)

    drain()
    state = state_fn(approval_payload)
    if state in {'approved', 'denied', 'expired'}:
        return state
    if timeout <= 0:
        return None

    approval_id = str(
        (approval_payload or {}).get('approval_id')
        or (approval_payload or {}).get('id')
        or ''
    ).strip()
    decided = wait_fn(approval_id, timeout_seconds=timeout, drain=drain)
    if decided in {'approved', 'denied', 'expired'}:
        return decided
    drain()
    state = state_fn(approval_payload)
    return state if state in {'approved', 'denied', 'expired'} else None


def sse_message(payload: dict[str, Any]) -> str:
    return f'event: message\ndata: {json.dumps(payload, default=str)}\n\n'


def form_elicitation_stream(
    *,
    session_id: str,
    rpc_id: str,
    call_id: Any,
    message: str,
    timeout_seconds: float,
    on_decision: Callable[[dict[str, Any] | None], dict[str, Any]],
    sleep: Callable[[float], None] = time.sleep,
    params: dict[str, Any] | None = None,
) -> Iterator[str]:
    """Yield the elicitation request, then the tools/call JSON-RPC response."""
    remember_open_elicitation(session_id, rpc_id)
    create_params = params if isinstance(params, dict) else classic_form_params(message=message)
    yield sse_message(
        {
            'jsonrpc': '2.0',
            'id': rpc_id,
            'method': 'elicitation/create',
            'params': create_params,
        }
    )
    result = wait_for_elicitation_result(
        session_id,
        rpc_id,
        timeout_seconds=timeout_seconds,
        sleep=sleep,
    )
    body = on_decision(result)
    yield sse_message({'jsonrpc': '2.0', 'id': call_id, 'result': body.get('result', body)})


def link_approval_stream(
    *,
    session_id: str,
    call_id: Any,
    timeout_seconds: float,
    approval_payload: dict[str, Any],
    on_page_state: Callable[[str | None], dict[str, Any]],
    sleep: Callable[[float], None] = time.sleep,
    elicit_params: dict[str, Any] | None = None,
    approval_state: Callable[[dict[str, Any]], str | None] | None = None,
    interval_seconds: float = 0.5,
    wait_decision: Callable[..., str | None] | None = None,
) -> Iterator[str]:
    """Hold tools/call open, optionally offer URL elicitation, wait for decide wake, then finish."""
    from secrets import token_hex

    rpc_id = ''
    if isinstance(elicit_params, dict) and elicit_params:
        rpc_id = token_hex(8)
        remember_open_elicitation(session_id, rpc_id)
        yield sse_message(
            {
                'jsonrpc': '2.0',
                'id': rpc_id,
                'method': 'elicitation/create',
                'params': elicit_params,
            }
        )
    state = wait_for_link_page_approval(
        approval_payload=approval_payload,
        session_id=session_id,
        rpc_id=rpc_id,
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
        sleep=sleep,
        approval_state=approval_state,
        wait_decision=wait_decision,
    )
    body = on_page_state(state)
    yield sse_message({'jsonrpc': '2.0', 'id': call_id, 'result': body.get('result', body)})


def form_elicitation_response(
    *,
    session_id: str,
    call_id: Any,
    message: str,
    on_decision: Callable[[dict[str, Any] | None], dict[str, Any]],
    params: dict[str, Any] | None = None,
) -> StreamingHttpResponse:
    from secrets import token_hex

    rpc_id = token_hex(8)
    stream = form_elicitation_stream(
        session_id=session_id,
        rpc_id=rpc_id,
        call_id=call_id,
        message=message,
        timeout_seconds=elicitation_wait_seconds(),
        on_decision=on_decision,
        params=params,
    )
    response = StreamingHttpResponse(stream, content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    if session_id:
        response['Mcp-Session-Id'] = session_id
    return response


def link_approval_response(
    *,
    session_id: str,
    call_id: Any,
    approval_payload: dict[str, Any],
    on_page_state: Callable[[str | None], dict[str, Any]],
    elicit_params: dict[str, Any] | None = None,
) -> StreamingHttpResponse:
    stream = link_approval_stream(
        session_id=session_id,
        call_id=call_id,
        timeout_seconds=elicitation_wait_seconds(),
        approval_payload=approval_payload,
        on_page_state=on_page_state,
        elicit_params=elicit_params,
    )
    response = StreamingHttpResponse(stream, content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    if session_id:
        response['Mcp-Session-Id'] = session_id
    return response
