"""``GET /v1/graph/node-aggregates``: the roll-up aggregate for a few named nodes.

A selected attack path names its hop nodes; each hop's finding count, worst
severity and exposure come from the same containment aggregate its roll-up
entry carries, so the path view and the roll-up never disagree. Each node reads
only its own containment subtree.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.graph_generation import optional_generation, verify_generation
from agent_bom.api.graph_store import containment_drilldown_graph
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph_node_aggregates import GraphNodeAggregatesResponse
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.scan_finding_read import suppressed_finding_ids
from agent_bom.graph.rollup import node_aggregate
from agent_bom.graph.semantic_layer import semantic_layer

MAX_NODE_AGGREGATES = 25

router = APIRouter(route_class=_GraphAdmissionRoute)


def _aggregates(store, *, tenant: str, scan_id: str, node_ids: list[str], suppressed: frozenset[str]) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    missing: list[str] = []
    for node_id in node_ids:
        graph = containment_drilldown_graph(store, node_id=node_id, scan_id=scan_id, tenant_id=tenant)
        aggregate = node_aggregate(graph, node_id, suppressed_finding_ids=suppressed)
        if aggregate is None:
            missing.append(node_id)
            continue
        rows.append({"node_id": node_id, "semantic_layer": semantic_layer(graph.nodes[node_id]), "aggregate": aggregate.to_dict()})
    return rows, missing


@router.get("/graph/node-aggregates", **documented(GraphNodeAggregatesResponse), tags=["graph"])
async def get_graph_node_aggregates(
    request: Request,
    node_id: list[str] = Query(..., description=f"Node ids to aggregate (at most {MAX_NODE_AGGREGATES}), e.g. a selected path's hops"),
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
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
