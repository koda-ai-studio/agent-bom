"""The cross-vendor slice of the attack-path queue, in queue order, with vendor-pair facets."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Optional

from fastapi import APIRouter, Query, Request

from agent_bom.api.graph_generation import pin_generation, verify_generation
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph_vendor_paths import GraphCrossVendorPathsResponse
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.routes.graph_routes.payloads import _serialize_attack_path_queue
from agent_bom.graph.attack_path_queue import AttackPathFilters
from agent_bom.graph.path_vendors import path_vendor_pair, vendor_pair_facets
from agent_bom.mcp_tools.exposure_queue import whole_queue

router = APIRouter(route_class=_GraphAdmissionRoute)

_VENDOR_PATTERN = r"^[a-z0-9_.-]*$"


def _hop_ids(paths: list[Any]) -> set[str]:
    return {hop for path in paths for hop in path.hops}


def _classify(
    paths: list[Any], endpoint_nodes: list[Any], *, source_vendor: str | None, target_vendor: str | None
) -> tuple[list[tuple[str, str]], list[Any]]:
    """Every crossing pair, and the crossing paths the vendor filter keeps, in queue order."""
    nodes_by_id = {node.id: node for node in endpoint_nodes}
    pairs: list[tuple[str, str]] = []
    selected: list[Any] = []
    for path in paths:
        pair = path_vendor_pair(path, nodes_by_id)
        if pair is None:
            continue
        pairs.append(pair)
        if (not source_vendor or pair[0] == source_vendor) and (not target_vendor or pair[1] == target_vendor):
            selected.append(path)
    return pairs, selected


@router.get("/graph/attack-paths/cross-vendor", **documented(GraphCrossVendorPathsResponse), tags=["graph"])
async def get_cross_vendor_attack_paths(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(
        None, max_length=128, description="Generation from the first page; required for continuation"
    ),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max attack paths"),
    source_vendor: Optional[str] = Query(
        None, description="Only paths whose source node is in this vendor", max_length=64, pattern=_VENDOR_PATTERN
    ),
    target_vendor: Optional[str] = Query(
        None, description="Only paths whose target node is in this vendor", max_length=64, pattern=_VENDOR_PATTERN
    ),
) -> dict:
    """Attack paths whose source and target nodes are recorded in different vendors.

    Vendors come from each endpoint's recorded ``cloud_provider``; agent-runtime
    surfaces (MCP, local) are not vendors and middle hops never qualify a path. Order is the global queue order.
    ``vendor_facets`` counts every cross-vendor path per pair, whatever pair
    is selected, so the chips beside the queue stay comparable.
    """
    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    identity = await _runtime._graph_store_call(
        pin_generation, graph_store, tenant=tenant, scan_id=scan_id or "", generation=snapshot_generation, offset=offset
    )
    page = await whole_queue(graph_store, tenant, identity[0], AttackPathFilters())
    ranked = page.ranked
    read = {"scan_id": ranked.scan_id, "tenant_id": tenant}
    endpoint_ids = {hop for path in ranked.paths for hop in (path.hops[:1] + path.hops[-1:])}
    endpoint_nodes = await _runtime._graph_store_call(graph_store.nodes_by_ids, **read, node_ids=endpoint_ids)
    crossing, selected = await _runtime._graph_compute_call(
        _classify, ranked.paths, endpoint_nodes, source_vendor=source_vendor, target_vendor=target_vendor
    )
    window = selected[offset : offset + limit]
    hop_ids = _hop_ids(window)
    window_nodes = await _runtime._graph_store_call(graph_store.nodes_by_ids, **read, node_ids=hop_ids)
    path_edges = await _runtime._graph_store_call(graph_store.edges_for_node_ids, **read, node_ids=hop_ids)
    stats = await _runtime._graph_store_call(graph_store.snapshot_stats, **read)
    filters = {key: value for key, value in (("source_vendor", source_vendor), ("target_vendor", target_vendor)) if value}
    payload = await _runtime._graph_compute_call(
        _serialize_attack_path_queue,
        scan_id=ranked.scan_id,
        tenant=tenant,
        created_at=ranked.created_at,
        nodes=window_nodes,
        path_edges=path_edges,
        paths=window,
        total=len(selected),
        offset=offset,
        limit=limit,
        stats=stats,
        path_source=page.source,
        materialized_paths=page.materialized_paths,
        derived_paths=page.derived_paths,
        ranked=replace(ranked, paths=window, total=len(selected)),
        filters={"cross_vendor": True, **filters},
    )
    await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(ranked.paths))
    payload["snapshot_generation"] = identity[1]
    payload["pagination"]["has_more"] = offset + len(window) < len(selected)
    payload["vendor_facets"] = {
        "unit": "paths",
        "snapshot_paths": ranked.total,
        "cross_vendor_paths": len(crossing),
        "pairs": vendor_pair_facets(crossing),
        "selected": filters or None,
        "covers_all_paths": page.covers_all_matches,
    }
    return payload
