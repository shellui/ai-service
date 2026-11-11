"""Push wake for MCP approval decisions (Redis pub/sub + in-process fallback)."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

CHANNEL_PREFIX = 'mcp_gateway:approval:'
RESULT_PREFIX = 'mcp_gateway:approval_result:'
RESULT_TTL_SECONDS = 600

_local_lock = threading.Lock()
_local_waiters: dict[str, list[queue.Queue[str]]] = {}


def approval_channel(approval_id: str) -> str:
    return f'{CHANNEL_PREFIX}{approval_id}'


def publish_approval_decision(approval_id: str, status: str) -> None:
    """Record and broadcast a terminal approval status to waiters."""
    approval_id = str(approval_id or '').strip()
    status = str(status or '').strip().lower()
    if not approval_id or status not in {'approved', 'denied', 'expired'}:
        return
    cache.set(f'{RESULT_PREFIX}{approval_id}', status, RESULT_TTL_SECONDS)
    _wake_local(approval_id, status)
    client = _redis_client()
    if client is None:
        return
    try:
        client.publish(approval_channel(approval_id), json.dumps({'status': status, 'approval_id': approval_id}))
    except Exception:
        logger.warning('MCP approval publish failed approval_id=%s', approval_id, exc_info=True)
    finally:
        try:
            client.close()
        except Exception:
            pass


def cached_approval_decision(approval_id: str) -> str | None:
    raw = cache.get(f'{RESULT_PREFIX}{str(approval_id or "").strip()}')
    status = str(raw or '').strip().lower()
    return status if status in {'approved', 'denied', 'expired'} else None


def wait_approval_decision(
    approval_id: str,
    *,
    timeout_seconds: float,
    drain: Callable[[], None] | None = None,
) -> str | None:
    """Block until a decision is published, or the timeout elapses.

    ``drain`` is an optional no-arg callback invoked each loop (e.g. clear elicitation).
    """
    approval_id = str(approval_id or '').strip()
    if not approval_id:
        return None
    timeout = max(0.0, float(timeout_seconds))
    known = cached_approval_decision(approval_id)
    if known:
        return known
    if timeout <= 0:
        return None

    local_q: queue.Queue[str] = queue.Queue(maxsize=1)
    with _local_lock:
        _local_waiters.setdefault(approval_id, []).append(local_q)

    pubsub = None
    client = None
    try:
        client = _redis_client()
        if client is not None:
            try:
                pubsub = client.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(approval_channel(approval_id))
            except Exception:
                logger.warning('MCP approval subscribe failed approval_id=%s', approval_id, exc_info=True)
                pubsub = None

        deadline = time.monotonic() + timeout
        while True:
            if drain is not None:
                try:
                    drain()
                except Exception:
                    pass
            known = cached_approval_decision(approval_id)
            if known:
                return known
            try:
                got = local_q.get_nowait()
                if got in {'approved', 'denied', 'expired'}:
                    return got
            except queue.Empty:
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return cached_approval_decision(approval_id)
            if pubsub is not None:
                try:
                    message = pubsub.get_message(timeout=min(0.5, remaining))
                except Exception:
                    message = None
                if isinstance(message, dict) and message.get('type') == 'message':
                    status = _status_from_payload(message.get('data'))
                    if status:
                        cache.set(f'{RESULT_PREFIX}{approval_id}', status, RESULT_TTL_SECONDS)
                        return status
            else:
                time.sleep(min(0.25, remaining))
    finally:
        with _local_lock:
            waiters = _local_waiters.get(approval_id) or []
            _local_waiters[approval_id] = [q for q in waiters if q is not local_q]
            if not _local_waiters[approval_id]:
                _local_waiters.pop(approval_id, None)
        if pubsub is not None:
            try:
                pubsub.unsubscribe()
                pubsub.close()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _wake_local(approval_id: str, status: str) -> None:
    with _local_lock:
        waiters = list(_local_waiters.get(approval_id) or [])
    for q in waiters:
        try:
            q.put_nowait(status)
        except queue.Full:
            pass


def _status_from_payload(raw: Any) -> str | None:
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', errors='replace')
    if isinstance(raw, str):
        text = raw.strip()
        if text in {'approved', 'denied', 'expired'}:
            return text
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict):
            status = str(data.get('status') or '').strip().lower()
            return status if status in {'approved', 'denied', 'expired'} else None
    return None


def _redis_client():
    url = (getattr(settings, 'REDIS_URL', '') or '').strip()
    if not url:
        return None
    try:
        import redis

        return redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=1.0)
    except Exception:
        logger.warning('MCP approval Redis client unavailable', exc_info=True)
        return None
