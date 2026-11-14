"""What a roll-up read needs beside the snapshot: its source graph and the tenant's suppressions."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from agent_bom.api.finding_suppression import suppression_revision
from agent_bom.api.graph_rollup_prewarm import load_rollup_source
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.scan_finding_read import suppressed_finding_ids
from agent_bom.security import sanitize_error


async def rollup_suppressions(tenant: str) -> str:
    """The suppression revision a cached roll-up is keyed on: an approval or revoke changes counts, not the snapshot."""
    return await _runtime._graph_store_call(suppression_revision, tenant)


async def current_coverage(store: Any, tenant: str, scan_id: str) -> dict[str, Any] | None:
    """The request's current-estate coverage, including a previous-generation label; None for a recorded scan."""
    reader = getattr(store, "current_view_coverage", None)
    if not scan_id.startswith("current-estate:") or not callable(reader):
        return None
    return dict(await _runtime._graph_store_call(reader, tenant_id=tenant, scan_id=scan_id))


async def with_current_coverage(payload: dict, store: Any, tenant: str) -> dict:
    """Freshness is request-local and must never be retained in a roll-up cache."""
    coverage = await current_coverage(store, tenant, str(payload.get("scan_id") or ""))
    return payload if coverage is None else {**payload, "collection_coverage": coverage}


async def rollup_source(graph_store: Any, tenant: str, scan_id: str, node: str | None, mode: str) -> tuple[Any, frozenset[str]]:
    """The graph one roll-up view reads, and the occurrences suppressed now."""
    try:
        # A drill-down reads only one container's subtree (its cost tracks the
        # answer, not the estate); the top level uses the store's aggregate-only
        # roll-up projection when it has one; attack-path mode needs the full
        # evidence records.
        graph = await _runtime._graph_store_call(
            load_rollup_source,
            graph_store,
            tenant_id=tenant,
            scan_id=scan_id,
            node=node,
            mode=mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    return graph, await _runtime._graph_store_call(suppressed_finding_ids, tenant)


__all__ = ["current_coverage", "rollup_source", "rollup_suppressions", "with_current_coverage"]
