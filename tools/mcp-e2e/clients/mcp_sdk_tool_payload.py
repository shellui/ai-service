"""Normalize MCP SDK tool objects for shared metadata assertions."""

from __future__ import annotations

from apps.connector.mcp_tool_metadata_checks import ANNOTATION_KEYS


def tool_payload_from_sdk(tool) -> dict:
    ann = getattr(tool, 'annotations', None)
    annotations: dict | None
    if ann is None:
        annotations = None
    elif hasattr(ann, 'model_dump'):
        annotations = ann.model_dump(exclude_none=False)
    elif isinstance(ann, dict):
        annotations = dict(ann)
    else:
        annotations = None
    if annotations is not None:
        for key in ANNOTATION_KEYS:
            if key not in annotations and hasattr(ann, key):
                annotations[key] = getattr(ann, key)
            annotations.setdefault(key, False)
    return {
        'name': getattr(tool, 'name', None),
        'title': getattr(tool, 'title', None),
        'description': getattr(tool, 'description', None),
        'annotations': annotations,
    }
