"""``GET /v1/graph/node-aggregates``: the roll-up aggregate for a few named nodes.

A selected attack path names its hop nodes; each hop's finding count, worst
severity and exposure come from the same containment aggregate its roll-up
entry carries, so the path view and the roll-up never disagree. Each node reads
only its own containment subtree.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.finding_suppression import suppression_revision
from agent_bom.api.graph_generation import optional_generation, pin_generation, verify_generation
from agent_bom.api.graph_store import containment_drilldown_graph
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph_node_aggregates import GraphNodeAggregatesResponse, GraphScopeFindingsResponse
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.scan_finding_read import suppressed_finding_ids
from agent_bom.graph.rollup_node import ScopeIndex
from agent_bom.graph.semantic_layer import semantic_layer

MAX_NODE_AGGREGATES = 25

router = APIRouter(route_class=_GraphAdmissionRoute)


def _scope_index_for(store, loaded: list[tuple[str, ScopeIndex]], *, tenant: str, scan_id: str, node_id: str, suppressed) -> ScopeIndex:
    """A graph already loaded for an ancestor scope holds this node's whole subtree; reuse it."""
    for root, index in loaded:
        if node_id == root or node_id in index.descendant_set(root):
            return index
    index = ScopeIndex(containment_drilldown_graph(store, node_id=node_id, scan_id=scan_id, tenant_id=tenant), suppressed)
    loaded.append((node_id, index))
    return index


def _aggregates(store, *, tenant: str, scan_id: str, node_ids: list[str], suppressed: frozenset[str]) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    missing: list[str] = []
    loaded: list[tuple[str, ScopeIndex]] = []
    for node_id in node_ids:
        index = _scope_index_for(store, loaded, tenant=tenant, scan_id=scan_id, node_id=node_id, suppressed=suppressed)
        aggregate = index.aggregate(node_id)
        if aggregate is None:
            missing.append(node_id)
            continue
        descendants = index.descendant_set(node_id)
        excluded = sorted(other for other in node_ids if other != node_id and other in descendants)
        rows.append(
            {
                "node_id": node_id,
                "semantic_layer": semantic_layer(index.graph.nodes[node_id]),
                "aggregate": aggregate.to_dict(),
                "finding_disclosure": index.disclosure(node_id, tuple(excluded)),
            }
        )
    return rows, missing


@router.get("/graph/node-aggregates", **documented(GraphNodeAggregatesResponse), tags=["graph"])
async def get_graph_node_aggregates(
    request: Request,
    node_id: list[str] = Query(..., description=f"Node ids to aggregate (at most {MAX_NODE_AGGREGATES}), e.g. a selected path's hops"),
    scan_id: Optional[str] = Query(None, max_length=256, description="Scan snapshot ID; latest if omitted"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision the caller pinned"),
) -> dict:
    """Each node's roll-up aggregate (issue_count, worst_severity, exposed_count, ...) and semantic layer."""
    ids = list(dict.fromkeys(item.strip() for item in node_id if item and item.strip()))
    if not ids:
        raise HTTPException(status_code=422, detail="node_id must name at least one node")
    if len(ids) > MAX_NODE_AGGREGATES:
        raise HTTPException(status_code=422, detail=f"At most {MAX_NODE_AGGREGATES} node_id values per request")
    tenant = _runtime._tenant(request)
    store = _runtime._get_graph_store_or_503()
    identity = await _runtime._graph_store_call(
        optional_generation, store, tenant=tenant, scan_id=scan_id or "", generation=snapshot_generation, offset=0
    )
    resolved_scan = identity[0] if identity is not None else scan_id or ""
    if not resolved_scan:
        resolved_scan = await _runtime._graph_store_call(store.latest_snapshot_id, tenant_id=tenant, snapshot_kind="scan") or ""
    if not resolved_scan:
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")
    suppressed = await _runtime._graph_store_call(suppressed_finding_ids, tenant)
    rows, missing = await _runtime._graph_store_call(
        _aggregates, store, tenant=tenant, scan_id=resolved_scan, node_ids=ids, suppressed=suppressed
    )
    if identity is not None:
        await _runtime._graph_store_call(verify_generation, store, tenant=tenant, identity=identity, has_rows=bool(rows))
    return {
        "scan_id": resolved_scan,
        "tenant_id": tenant,
        "snapshot_generation": identity[1] if identity is not None else None,
        "aggregates": rows,
        "missing_node_ids": missing,
    }


__all__ = ["MAX_NODE_AGGREGATES", "router"]


def _scope_findings(
    store, *, tenant: str, scan_id: str, node_id: str, suppressed: frozenset[str], excluded: tuple[str, ...] = ()
) -> list[dict]:
    index = ScopeIndex(containment_drilldown_graph(store, node_id=node_id, scan_id=scan_id, tenant_id=tenant), suppressed)
    if node_id not in index.graph.nodes:
        raise HTTPException(404, "Scope not found in this snapshot.")
    descendants = index.descendant_set(node_id)
    if any(child == node_id or child not in descendants for child in excluded):
        raise HTTPException(422, "Excluded scopes must be descendants of the selected scope.")
    return index.findings(node_id, excluded)


@router.get("/graph/scope-findings", **documented(GraphScopeFindingsResponse), tags=["graph"])
async def get_scope_findings(
    request: Request,
    node_id: str = Query(..., min_length=1, max_length=2048),
    scan_id: Optional[str] = Query(None, max_length=256),
    snapshot_generation: Optional[str] = Query(None, max_length=128),
    finding_revision: Optional[str] = Query(None, max_length=128),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    exclude_node_id: list[str] = Query(default=[], max_length=25, description="Descendant scopes disclosed separately; at most 25."),
) -> dict:
    """Open issues on the roll-up count basis; tenant-scoped and revision-pinned pages."""
    tenant = _runtime._tenant(request)
    if any(not value or len(value) > 2048 for value in exclude_node_id):
        raise HTTPException(422, "Excluded scope identifiers must contain 1 to 2048 characters.")
    store = _runtime._get_graph_store_or_503()
    identity = await _runtime._graph_store_call(
        pin_generation, store, tenant=tenant, scan_id=scan_id or "", generation=snapshot_generation, offset=offset
    )
    revision = await _runtime._graph_store_call(suppression_revision, tenant)
    if offset and not finding_revision:
        raise HTTPException(422, "Continuation requires finding_revision; restart the query.")
    if finding_revision is not None and finding_revision != revision:
        raise HTTPException(409, "Finding suppressions changed; restart the query.")
    suppressed = await _runtime._graph_store_call(suppressed_finding_ids, tenant)
    rows = await _runtime._graph_store_call(
        _scope_findings,
        store,
        tenant=tenant,
        scan_id=identity[0],
        node_id=node_id,
        suppressed=suppressed,
        excluded=tuple(sorted(set(exclude_node_id))),
    )
    await _runtime._graph_store_call(verify_generation, store, tenant=tenant, identity=identity, has_rows=bool(rows))
    if revision != await _runtime._graph_store_call(suppression_revision, tenant):
        raise HTTPException(409, "Finding suppressions changed during the read; restart the query.")
    return {
        "scan_id": identity[0],
        "tenant_id": tenant,
        "snapshot_generation": identity[1],
        "node_id": node_id,
        "finding_revision": revision,
        "total": len(rows),
        "offset": offset,
        "limit": limit,
        "findings": rows[offset : offset + limit],
    }
