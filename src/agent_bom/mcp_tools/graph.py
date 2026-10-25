"""Graph-native MCP tools for headless agent consumers."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import uuid
from collections.abc import Awaitable
from typing import Any

from agent_bom.api import audit_log, graph_scan_ids
from agent_bom.graph.edge_lookup import _EdgeLookup
from agent_bom.graph.exposure import _exposure_path_for_attack_path, _exposure_ref_for_node, _exposure_relationships_for_path
from agent_bom.mcp_errors import (
    CODE_INTERNAL_UNEXPECTED,
    CODE_NOT_FOUND_RESOURCE,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    CODE_VALIDATION_MISSING_REQUIRED,
    mcp_error_json,
)
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools import deploy_gate as _deploy_gate
from agent_bom.mcp_tools import exposure_queue as _exposure_queue
from agent_bom.mcp_tools.estate_refusal import retryable_estate_refusal
from agent_bom.mcp_tools.storage import default_graph_store

logger = logging.getLogger(__name__)

_STORAGE_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (OSError, sqlite3.OperationalError)
try:
    from psycopg import OperationalError as _PostgresOperationalError
except ImportError:
    pass  # Postgres is an optional deployment extra.
else:
    _STORAGE_UNAVAILABLE_ERRORS += (_PostgresOperationalError,)


def _graph_read_error(exc: Exception) -> str:
    refusal = retryable_estate_refusal(exc)
    if refusal is not None:
        return refusal
    if isinstance(exc, _STORAGE_UNAVAILABLE_ERRORS):
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, "Graph storage is temporarily unavailable; retry the request.")
    logger.error("MCP graph tool error; internal details withheld")
    return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


async def guarded_graph_read(call: Awaitable[str]) -> str:
    """The graph tools' one error boundary: storage outages retry, anything else is withheld."""
    try:
        return await call
    except Exception as exc:
        return _graph_read_error(exc)


async def graph_correlate_impl(
    *,
    name: str,
    scan_ids: list[str],
    max_age_hours: int,
    idempotency_key: str,
    reason: str,
    allow_stale: bool = False,
    tenant_id: str = "default",
    _service=None,
    _truncate_response=None,
    _authenticated_actor: str = "",
    **_audit: str,
) -> str:
    """Create a tenant-scoped immutable graph correlation."""
    from agent_bom.graph.correlation_service import CorrelationRequest, CorrelationServiceError, get_graph_correlation_service

    if not name.strip():
        return mcp_error_json(CODE_VALIDATION_MISSING_REQUIRED, "name is required", details={"argument": "name"})
    if not idempotency_key.strip():
        return mcp_error_json(
            CODE_VALIDATION_MISSING_REQUIRED,
            "idempotency_key is required",
            details={"argument": "idempotency_key"},
        )
    if len(reason.strip()) < 8:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "reason must be at least 8 characters",
            details={"argument": "reason"},
        )
    if not 2 <= len(scan_ids) <= 32 or len(set(scan_ids)) != len(scan_ids) or any(not item.strip() for item in scan_ids):
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "scan_ids must contain between 2 and 32 distinct non-empty snapshot ids",
            details={"argument": "scan_ids"},
        )
    if not 1 <= max_age_hours <= 8760:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "max_age_hours must be between 1 and 8760",
            details={"argument": "max_age_hours", "value": max_age_hours},
        )
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        if _service is None:
            _get_graph_store = default_graph_store

            _service = await get_graph_correlation_service(_get_graph_store(), tenant_id)
        run = await _service.submit(
            CorrelationRequest(
                correlation_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                idempotency_key=idempotency_key,
                name=name.strip(),
                scan_ids=tuple(scan_ids),
                max_age_hours=max_age_hours,
                allow_stale=allow_stale,
            )
        )
        audit_log.log_action(
            "graph.correlation.create",
            actor=(_authenticated_actor or "mcp-operator").strip(),
            resource=f"graph/correlation/{run.correlation_id}",
            tenant_id=tenant_id,
            source_count=len(run.input_manifest),
            max_age_hours=run.max_age_hours,
            allow_stale=run.allow_stale,
            reason_provided=True,
        )
        encoded = json.dumps(run.to_dict(), separators=(",", ":"), default=str)
        return _truncate_response(encoded) if _truncate_response is not None else encoded
    except CorrelationServiceError as exc:
        code = CODE_NOT_FOUND_RESOURCE if exc.code == "input_snapshot_not_found" else CODE_VALIDATION_INVALID_ARGUMENT
        return mcp_error_json(code, exc.code)
    except ValueError:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "idempotency_key_conflict")
    except Exception:
        logger.error("MCP graph correlation creation failed; internal details withheld")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


async def graph_correlation_status_impl(
    correlation_id: str,
    *,
    tenant_id: str = "default",
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    """Read one tenant-scoped graph correlation run."""

    if not correlation_id.strip():
        return mcp_error_json(
            CODE_VALIDATION_MISSING_REQUIRED,
            "correlation_id is required",
            details={"argument": "correlation_id"},
        )
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        if _get_graph_store is None:
            _get_graph_store = default_graph_store
        run = await asyncio.to_thread(
            _get_graph_store().get_correlation_run,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        if run is None:
            return mcp_error_json(CODE_NOT_FOUND_RESOURCE, "correlation_not_found")
        audit_log.log_action(
            "graph.correlation.read",
            actor="mcp-reader",
            resource=f"graph/correlation/{correlation_id}",
            tenant_id=tenant_id,
            status=run.status.value,
        )
        encoded = json.dumps(run.to_dict(), separators=(",", ":"), default=str)
        return _truncate_response(encoded) if _truncate_response is not None else encoded
    except Exception:
        logger.error("MCP graph correlation status failed; internal details withheld")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


# Retain private compatibility helpers while keeping the projection canonical.
_node_ref = _exposure_ref_for_node
_relationship_refs = _exposure_relationships_for_path


def _exposure_path_payload(
    path: Any,
    *,
    nodes_by_id: dict[str, Any],
    edges: list[Any],
    rank: int,
    scan_id: str,
    edge_lookup: _EdgeLookup | None = None,
) -> dict[str, Any]:
    payload = _exposure_path_for_attack_path(
        path,
        nodes_by_id=nodes_by_id,
        edges=edges,
        rank=rank,
        scan_id=scan_id,
        edge_lookup=edge_lookup,
    )
    payload["provenance"] = {"source": "mcp_exposure_paths", "scanId": scan_id}
    return payload


def _candidate_matches_path(candidate: str, path: dict[str, Any]) -> bool:
    needle = candidate.strip().lower()
    if not needle:
        return True
    haystack: list[str] = [
        str(path.get("id", "")),
        str(path.get("label", "")),
        str(path.get("summary", "")),
        *[str(value) for value in path.get("nodeIds", [])],
        *[str(value) for value in path.get("edgeIds", [])],
        *[str(value) for value in path.get("findings", [])],
        *[str(value) for value in path.get("reachableTools", [])],
    ]
    for endpoint in ("source", "target"):
        value = path.get(endpoint)
        if isinstance(value, dict):
            haystack.extend(str(value.get(key, "")) for key in ("id", "label", "role", "entityType"))
    for hop in path.get("hops", []):
        if isinstance(hop, dict):
            haystack.extend(str(hop.get(key, "")) for key in ("id", "label", "role", "entityType"))
    return any(needle in value.lower() for value in haystack)


async def _resolve_exposure_snapshot(tenant_id: str, scan_id: str | None) -> tuple[str | None, str | None]:
    if not scan_id:
        return scan_id, None
    try:
        return await asyncio.to_thread(graph_scan_ids.resolve_graph_scan_id, tenant_id, scan_id), None
    except _STORAGE_UNAVAILABLE_ERRORS as exc:
        return None, _graph_read_error(exc)


async def exposure_paths_impl(
    *,
    tenant_id: str = "default",
    view: str = "summary",
    _get_graph_store=None,
    _truncate_response=None,
    **query: Any,
) -> str:
    """MCP entrypoint: resolve the tool tenant, default to the compact summary view."""
    return await exposure_paths_for_tenant(
        tenant_id=resolve_mcp_tool_tenant_id(tenant_id),
        view=view,
        _get_graph_store=_get_graph_store,
        _truncate_response=_truncate_response,
        **query,
    )


async def exposure_paths_for_tenant(*, tenant_id: str, _get_graph_store=None, _truncate_response=None, **query: Any) -> str:
    """Return ranked ExposurePath JSON for an already-authenticated tenant.

    Callers must pass a tenant established by their own authentication (the
    REST request principal); MCP tools go through ``exposure_paths_impl``.
    """
    return await guarded_graph_read(
        _exposure_queue.exposure_paths_for_tenant(
            tenant_id=tenant_id,
            _get_graph_store=_get_graph_store or default_graph_store,
            _resolve_scan=_resolve_exposure_snapshot,
            _truncate_response=_truncate_response,
            **query,
        )
    )


async def deploy_decision_impl(
    *, candidate: str, tenant_id: str = "default", _get_graph_store=None, _truncate_response=None, **options: Any
) -> str:
    return await deploy_decision_for_tenant(
        candidate=candidate,
        tenant_id=resolve_mcp_tool_tenant_id(tenant_id),
        _get_graph_store=_get_graph_store,
        _truncate_response=_truncate_response,
        **options,
    )


async def deploy_decision_for_tenant(
    *, candidate: str, tenant_id: str, _get_graph_store=None, _truncate_response=None, **options: Any
) -> str:
    """Deploy gate over every stored path of the tenant's pinned snapshot."""
    return await guarded_graph_read(
        _deploy_gate.deploy_decision_for_tenant(
            candidate=candidate,
            tenant_id=tenant_id,
            _get_graph_store=_get_graph_store or default_graph_store,
            _resolve_scan=_resolve_exposure_snapshot,
            _truncate_response=_truncate_response,
            **options,
        )
    )
