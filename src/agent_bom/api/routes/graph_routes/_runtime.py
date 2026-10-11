"""Graph route runtime: tenant + store resolution and off-loop store/compute calls.

Route modules call these through the module (``_runtime._tenant(...)``) so a
single patch point covers every graph route.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Callable, TypeVar

from fastapi import HTTPException, Request

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
        from agent_bom.api.graph_scan_ids import resolve_graph_scan_id

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
