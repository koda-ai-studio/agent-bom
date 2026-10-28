"""The cross-vendor slice of the attack-path queue, in queue order, with vendor-pair facets."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request

from agent_bom.api.graph_generation import pin_generation, verify_generation
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph_vendor_paths import GraphCrossVendorPathsResponse
from agent_bom.api.request_contract import reject_unknown_query_params
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.routes.graph_routes.path_cursor import path_continuation, path_cursor_scope, path_page_cursors
from agent_bom.api.routes.graph_routes.payloads import _serialize_attack_path_queue
from agent_bom.graph.attack_path_queue import AttackPathFilters, RankedPathPage
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


_Slice = tuple[Any, list[Any], int, list[dict[str, Any]], tuple[str, int, int], bool]


async def _indexed_slice(
    graph_store: Any, tenant: str, scan_id: str, offset: int, limit: int, vendors: dict[str, str | None]
) -> _Slice | None:
    """Two indexed queries over the stored path rows, or ``None`` without a current index."""
    reader = getattr(graph_store, "snapshot_cross_vendor_page", None)
    if reader is None:
        return None
    stored = await _runtime._graph_store_call(reader, tenant_id=tenant, scan_id=scan_id, offset=offset, limit=limit, **vendors)
    if stored is None:
        return None
    ranked = RankedPathPage(stored.scan_id, stored.created_at, stored.paths, stored.total, stored.snapshot_total)
    pairs = [{"source_vendor": source, "target_vendor": target, "paths": count} for source, target, count in stored.pairs]
    return ranked, stored.paths, stored.total, pairs, ("derived_graph_paths", 0, stored.snapshot_total), True


async def _whole_queue_slice(
    graph_store: Any, tenant: str, scan_id: str, offset: int, limit: int, vendors: dict[str, str | None]
) -> _Slice:
    """Fallback for stores and snapshots without the stored vendor columns: classify the ranked queue."""
    page = await whole_queue(graph_store, tenant, scan_id, AttackPathFilters())
    ranked = page.ranked
    endpoint_ids = {hop for path in ranked.paths for hop in (path.hops[:1] + path.hops[-1:])}
    endpoint_nodes = await _runtime._graph_store_call(
        graph_store.nodes_by_ids, scan_id=ranked.scan_id, tenant_id=tenant, node_ids=endpoint_ids
    )
    crossing, selected = await _runtime._graph_compute_call(_classify, ranked.paths, endpoint_nodes, **vendors)
    ranked = replace(ranked, snapshot_total=ranked.total)
    source = (page.source, page.materialized_paths, page.derived_paths)
    return ranked, selected[offset : offset + limit], len(selected), vendor_pair_facets(crossing), source, page.covers_all_matches


@router.get(
    "/graph/attack-paths/cross-vendor",
    **documented(GraphCrossVendorPathsResponse),
    tags=["graph"],
    dependencies=[Depends(reject_unknown_query_params)],
)
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
    cursor: Optional[str] = Query(None, max_length=1024, description="next_cursor from the previous page (replaces offset)"),
) -> dict:
    """Attack paths whose source and target nodes are recorded in different vendors.

    Vendors come from each endpoint's recorded ``cloud_provider``; agent-runtime
    surfaces (MCP, local) are not vendors and middle hops never qualify a path. Order is the global queue order.
    ``vendor_facets`` counts every cross-vendor path per pair, whatever pair
    is selected, so the chips beside the queue stay comparable.
    """
    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    vendors = {"source_vendor": source_vendor, "target_vendor": target_vendor}
    scope = path_cursor_scope("attack-paths-cross-vendor", tenant, scan_id, {key: value for key, value in vendors.items() if value})
    if cursor:
        offset, snapshot_generation = path_continuation(cursor, scope, offset=offset, generation=snapshot_generation)
    identity = await _runtime._graph_store_call(
        pin_generation, graph_store, tenant=tenant, scan_id=scan_id or "", generation=snapshot_generation, offset=offset
    )
    queue = await _indexed_slice(graph_store, tenant, identity[0], offset, limit, vendors)
    if queue is None:
        queue = await _whole_queue_slice(graph_store, tenant, identity[0], offset, limit, vendors)
    ranked, window, total, pairs, source, covers_all = queue
    read = {"scan_id": ranked.scan_id, "tenant_id": tenant}
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
        total=total,
        offset=offset,
        limit=limit,
        stats=stats,
        path_source=source[0],
        materialized_paths=source[1],
        derived_paths=source[2],
        ranked=replace(ranked, paths=window, total=total),
        filters={"cross_vendor": True, **filters},
    )
    await _runtime._graph_store_call(
        verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(window or ranked.snapshot_total)
    )
    payload["snapshot_generation"] = identity[1]
    payload["pagination"].update(path_page_cursors(scope, identity[1], offset, len(window), total, cursor))
    payload["vendor_facets"] = {
        "unit": "paths",
        "snapshot_paths": ranked.snapshot_total,
        "cross_vendor_paths": sum(pair["paths"] for pair in pairs),
        "pairs": pairs,
        "selected": filters or None,
        "covers_all_paths": covers_all,
    }
    return payload
