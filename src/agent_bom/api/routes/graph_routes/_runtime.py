"""Graph route runtime: tenant + store resolution and off-loop store/compute calls.

Route modules call these through the module (``_runtime._tenant(...)``) so a
single patch point covers every graph route.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Callable, TypeVar

from fastapi import HTTPException, Request

from agent_bom.api.graph_node_alias import resolve_snapshot_node_id, resolve_snapshot_node_ids
from agent_bom.api.graph_scan_ids import resolve_graph_scan_id
from agent_bom.api.neptune_graph import NeptuneGraphStoreUnsupportedOperationError
from agent_bom.api.routes.graph_routes._admission import _graph_request_admitted
from agent_bom.api.stores import _get_graph_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.cloud.runtime_graph_evidence import _enrich_loaded_graph_runtime_evidence
from agent_bom.security import sanitize_error

if TYPE_CHECKING:
    from agent_bom.api.graph_store import GraphStoreProtocol


_GraphCallResult = TypeVar("_GraphCallResult")


def _get_graph_store_or_503() -> GraphStoreProtocol:
    """Resolve the active graph store backend."""
    return _get_graph_store()


def _tenant(request: Request) -> str:
    """Extract tenant_id from request (set by auth middleware)."""
    return require_request_tenant_id(request)


async def _graph_store_call(fn: Callable[..., _GraphCallResult], /, *args: Any, **kwargs: Any) -> _GraphCallResult:
    """Run sync graph store methods off the event loop.

    A ``scan_id`` that names one of the caller's scan jobs is resolved to the
    snapshot id its report was stored under, so every graph read accepts the
    job id a push or scan response returned.
    """
    if kwargs.get("scan_id") and "tenant_id" in kwargs:
        kwargs["scan_id"] = await asyncio.to_thread(resolve_graph_scan_id, str(kwargs["tenant_id"] or ""), str(kwargs["scan_id"]))
    try:
        if _graph_request_admitted.get():
            return await asyncio.to_thread(fn, *args, **kwargs)
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc
    except NeptuneGraphStoreUnsupportedOperationError as exc:
        raise HTTPException(status_code=501, detail=sanitize_error(exc)) from exc


async def _load_graph_for_investigation(
    graph_store: Any,
    *,
    scan_id: str | None,
    tenant_id: str,
    **load_kwargs: Any,
) -> Any:
    """load_graph + runtime-evidence enrich for investigation surfaces."""
    graph = await _graph_store_call(
        graph_store.load_graph,
        scan_id=scan_id or "",
        tenant_id=tenant_id,
        **load_kwargs,
    )
    return await _graph_compute_call(_enrich_loaded_graph_runtime_evidence, graph, tenant_id)


async def _graph_compute_call(fn: Callable[..., _GraphCallResult], /, *args: Any, **kwargs: Any) -> _GraphCallResult:
    """Run CPU-heavy graph derivation and serialization off the event loop."""
    try:
        if _graph_request_admitted.get():
            return await asyncio.to_thread(fn, *args, **kwargs)
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc
    except NeptuneGraphStoreUnsupportedOperationError as exc:
        raise HTTPException(status_code=501, detail=sanitize_error(exc)) from exc


async def require_graph_snapshot_ids(store: Any, tenant_id: str, *scan_ids: str) -> list[str]:
    """Resolve explicit scan ids; 404 when any is not a snapshot of this tenant.

    A read addressed to an unknown or another tenant's snapshot must not answer
    ``200 complete:true`` with empty data, which reads as "nothing found"
    rather than "no such snapshot".
    """
    resolved = [await asyncio.to_thread(resolve_graph_scan_id, tenant_id, scan_id) for scan_id in scan_ids]
    try:
        found = await _graph_store_call(store.snapshots_by_ids, tenant_id=tenant_id, scan_ids=set(resolved))
    except HTTPException as exc:
        if exc.status_code != 501:
            raise
        # A backend that cannot list snapshots (experimental Neptune) answers the read itself.
        return resolved
    if set(resolved) - {str(row.get("scan_id") or "") for row in found or []}:
        raise HTTPException(status_code=404, detail="Graph snapshot not found for this tenant.")
    return resolved


async def resolve_node_id(store: Any, tenant_id: str, scan_id: str | None, node_id: str) -> tuple[str, str | None]:
    """``(id to read, resolved_from)`` for a node id addressed by a read; see :mod:`agent_bom.graph.node_alias_resolution`."""
    if not node_id:
        return node_id, None
    return await _graph_store_call(resolve_snapshot_node_id, store, tenant_id=tenant_id, scan_id=scan_id or "", node_id=node_id)


async def resolve_query_roots(store: Any, tenant_id: str, scan_id: str, body: Any) -> tuple[Any, dict[str, str], list[str]]:
    """``(body with canonical roots, {given id: canonical id}, roots not in the snapshot as the caller sent them)``."""
    roots, resolved = await _graph_store_call(
        resolve_snapshot_node_ids, store, tenant_id=tenant_id, scan_id=scan_id, node_ids=list(body.roots)
    )
    known = {node.id for node in await _graph_store_call(store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=set(roots))}
    given = {canonical: alias for alias, canonical in resolved.items()}
    missing = [given.get(root, root) for root in roots if root not in known]
    return (body.model_copy(update={"roots": roots}) if resolved else body), resolved, missing
