"""Tenant (company) fields on MCP tools: hidden from agents, bound from the agent token."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from shellui_django.mcp.routing import McpToolArgumentError

TENANT_FIELD_NAMES = frozenset({'company_id', 'companyId'})


def is_tenant_field(name: str) -> bool:
    return str(name) in TENANT_FIELD_NAMES


def partition_field_names(names: list[str]) -> tuple[list[str], list[str]]:
    agent: list[str] = []
    tenant: list[str] = []
    for name in names:
        key = str(name)
        if is_tenant_field(key):
            tenant.append(key)
        else:
            agent.append(key)
    return agent, tenant


def agent_company_id(agent_claims: dict[str, Any]) -> int:
    raw = agent_claims.get('company_id')
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise McpToolArgumentError('Agent token is missing a numeric company_id.') from exc


def tenant_binding_from_meta(meta: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, loc in (
        ('tenant_path_params', 'path_params'),
        ('tenant_query_fields', 'query'),
        ('tenant_body_fields', 'body'),
    ):
        raw = meta.get(key)
        if isinstance(raw, list) and raw:
            out[loc] = [str(v) for v in raw if is_tenant_field(str(v))]
    return out


def merge_tenant_bindings(*bindings: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for binding in bindings:
        for loc, names in binding.items():
            bucket = merged.setdefault(loc, [])
            for name in names:
                if name not in bucket:
                    bucket.append(name)
    return merged


def _tenant_values_in_bucket(bucket: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in bucket.items():
        if is_tenant_field(str(key)):
            found[str(key)] = value
    return found


def _coerce_tenant_value(value: Any, company_id: int) -> Any:
    if isinstance(value, bool):
        return company_id
    if isinstance(value, int) and not isinstance(value, bool):
        return company_id
    if isinstance(value, float):
        return float(company_id)
    return str(company_id)


def _reject_tenant_mismatch(
    supplied: dict[str, Any],
    *,
    company_id: int,
) -> None:
    for key, value in supplied.items():
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        try:
            if int(value) != int(company_id):
                raise McpToolArgumentError(
                    f'Tenant field `{key}` does not match the authenticated company.'
                )
        except (TypeError, ValueError):
            if text != str(company_id):
                raise McpToolArgumentError(
                    f'Tenant field `{key}` does not match the authenticated company.'
                )


def apply_tenant_to_arguments(
    arguments: dict[str, Any],
    agent_claims: dict[str, Any],
    meta: dict[str, Any],
    *,
    reject_mismatch: bool = True,
) -> dict[str, Any]:
    """Inject company from the agent token; reject cross-tenant overrides."""
    company_id = agent_company_id(agent_claims)
    binding = tenant_binding_from_meta(meta)
    out = deepcopy(arguments if isinstance(arguments, dict) else {})

    for loc in ('path_params', 'query', 'body'):
        bucket = out.get(loc)
        if bucket is None:
            continue
        if not isinstance(bucket, dict):
            raise McpToolArgumentError(f'{loc} must be an object.')
        supplied = _tenant_values_in_bucket(bucket)
        if reject_mismatch and supplied:
            _reject_tenant_mismatch(supplied, company_id=company_id)
        for key in list(bucket.keys()):
            if is_tenant_field(str(key)):
                del bucket[key]

    for loc, field_names in binding.items():
        if not field_names:
            continue
        bucket = out.setdefault(loc, {})
        if not isinstance(bucket, dict):
            raise McpToolArgumentError(f'{loc} must be an object.')
        for field in field_names:
            sample = bucket.get(field)
            bucket[field] = _coerce_tenant_value(sample, company_id)

    return out


def _strip_tenant_properties(obj: dict[str, Any]) -> None:
    props = obj.get('properties')
    if not isinstance(props, dict):
        return
    for key in list(props.keys()):
        if is_tenant_field(str(key)):
            del props[key]
    required = obj.get('required')
    if isinstance(required, list):
        obj['required'] = [str(k) for k in required if not is_tenant_field(str(k)) and str(k) in props]


def strip_tenant_fields_from_input_schema(input_schema: dict[str, Any]) -> dict[str, list[str]]:
    """Remove tenant fields from a tool ``inputSchema``; return binding by location."""
    binding: dict[str, list[str]] = {}
    if not isinstance(input_schema, dict):
        return binding
    props = input_schema.get('properties')
    if not isinstance(props, dict):
        return binding

    path_params = props.get('path_params')
    if isinstance(path_params, dict):
        before = list((path_params.get('properties') or {}).keys())
        _strip_tenant_properties(path_params)
        tenant = [str(k) for k in before if is_tenant_field(str(k))]
        if tenant:
            binding['path_params'] = tenant

    for loc in ('query', 'body'):
        section = props.get(loc)
        if isinstance(section, dict):
            before = list((section.get('properties') or {}).keys())
            _strip_tenant_properties(section)
            tenant = [str(k) for k in before if is_tenant_field(str(k))]
            if tenant:
                binding[loc] = tenant

    top_required = input_schema.get('required')
    if isinstance(top_required, list) and 'path_params' in top_required:
        path_props = (props.get('path_params') or {}).get('properties') or {}
        path_required = (props.get('path_params') or {}).get('required') or []
        if isinstance(path_props, dict) and isinstance(path_required, list):
            if path_required and not path_props:
                input_schema['required'] = [k for k in top_required if k != 'path_params']
            elif not path_required and 'path_params' in props:
                props['path_params'].pop('required', None)

    return binding


def apply_tenant_meta_from_binding(meta: dict[str, Any], binding: dict[str, list[str]]) -> dict[str, Any]:
    out = dict(meta)
    path_params = list(out.get('path_params') or [])
    agent_path, tenant_path = partition_field_names([str(p) for p in path_params])
    if binding.get('path_params'):
        tenant_path = binding['path_params']
        agent_path = [p for p in path_params if p not in tenant_path]
    out['path_params'] = path_params
    if tenant_path:
        out['tenant_path_params'] = tenant_path

    query_fields = list(out.get('query_fields') or [])
    if binding.get('query'):
        tenant_query = binding['query']
        agent_query = [f for f in query_fields if f not in tenant_query]
    else:
        agent_query, tenant_query = partition_field_names([str(f) for f in query_fields])
    if query_fields or tenant_query:
        out['query_fields'] = agent_query or None
        if tenant_query:
            out['tenant_query_fields'] = tenant_query
    query_required = list(out.get('query_required') or [])
    if query_required:
        out['query_required'] = [f for f in query_required if f in (out.get('query_fields') or [])] or None

    body_fields = list(out.get('body_fields') or [])
    if binding.get('body'):
        tenant_body = binding['body']
        agent_body = [f for f in body_fields if f not in tenant_body]
    else:
        agent_body, tenant_body = partition_field_names([str(f) for f in body_fields])
    if body_fields or tenant_body:
        out['body_fields'] = agent_body or None
        if tenant_body:
            out['tenant_body_fields'] = tenant_body
    body_required = list(out.get('body_required') or [])
    if body_required:
        out['body_required'] = [f for f in body_required if f in (out.get('body_fields') or [])] or None

    return out


def input_schema_has_tenant_fields(input_schema: dict[str, Any]) -> list[str]:
    """Return JSON paths where tenant fields still appear (for tests and audits)."""
    paths: list[str] = []
    if not isinstance(input_schema, dict):
        return paths
    props = input_schema.get('properties')
    if not isinstance(props, dict):
        return paths
    for loc in ('path_params', 'query', 'body'):
        section = props.get(loc)
        if not isinstance(section, dict):
            continue
        sub = section.get('properties')
        if not isinstance(sub, dict):
            continue
        for key in sub:
            if is_tenant_field(str(key)):
                paths.append(f'properties.{loc}.properties.{key}')
    return paths
