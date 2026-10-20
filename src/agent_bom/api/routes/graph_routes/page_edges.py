"""The ``/v1/graph`` node page's incident edges, bounded, with no ranked node left edgeless."""

from __future__ import annotations

from typing import Any

from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes.payloads import _NODE_PAGE_EDGE_LIMIT

# Edgeless ranked nodes re-anchored one by one after the batch read; the batch reads this many edges per node.
_EDGELESS_ANCHOR_LIMIT = 50
_ANCHOR_BATCH_EDGES_PER_NODE = 4


async def _page_edges(graph_store: Any, *, scan_id: str, tenant: str, node_ids: set[str]) -> tuple[list[Any], bool]:
    """The page's incident edges within budget, plus one anchor for any ranked node it left edgeless."""
    edges = await _runtime._graph_store_call(
        graph_store.edges_for_node_ids, scan_id=scan_id, tenant_id=tenant, node_ids=node_ids, limit=_NODE_PAGE_EDGE_LIMIT + 1
    )
    truncated = len(edges) > _NODE_PAGE_EDGE_LIMIT
    edges = edges[:_NODE_PAGE_EDGE_LIMIT]
    # The store bounds each endpoint walk, so a hub can lose every edge even when the page is not truncated.
    anchors = await _anchor_edgeless_nodes(graph_store, scan_id=scan_id, tenant=tenant, node_ids=node_ids, edges=edges)
    if anchors:
        edges = _covering_selection([*edges, *anchors], node_ids)
    return edges, truncated


def _covering_selection(edges: list[Any], node_ids: set[str]) -> list[Any]:
    """At most the edge budget, giving every ranked node one edge before any node a second.

    Covering edges are taken first in query order; the rest fill the budget in
    the same order, so only edges whose endpoints are already connected drop.
    """
    covered: set[str] = set()
    chosen: set[int] = set()
    for index, edge in enumerate(edges):
        ends = {edge.source, edge.target} & node_ids
        if ends - covered:
            covered |= ends
            chosen.add(index)
    for index in range(len(edges)):
        if len(chosen) >= _NODE_PAGE_EDGE_LIMIT:
            break
        chosen.add(index)
    return [edge for index, edge in enumerate(edges) if index in chosen][:_NODE_PAGE_EDGE_LIMIT]


async def _anchor_edgeless_nodes(graph_store: Any, *, scan_id: str, tenant: str, node_ids: set[str], edges: list[Any]) -> list[Any]:
    """One edge for each ranked node the bounded edge read left with none.

    A hub (one advisory held by dozens of packages) can sort every incident
    edge past the budget and render as an orphan. One bounded batch read of the
    edgeless nodes' incident edges anchors most; a capped per-node read the rest.
    """
    touched = {edge.source for edge in edges} | {edge.target for edge in edges}
    orphans = node_ids - touched
    if not orphans:
        return []
    batch = await _runtime._graph_store_call(
        graph_store.edges_for_node_ids,
        scan_id=scan_id,
        tenant_id=tenant,
        node_ids=orphans,
        limit=_ANCHOR_BATCH_EDGES_PER_NODE * len(orphans),
    )
    anchors: dict[str, Any] = {}
    for edge in batch:
        for endpoint in (edge.target, edge.source):
            if endpoint in orphans and endpoint not in anchors:
                anchors[endpoint] = edge
                break
    for node_id in sorted(orphans - set(anchors))[:_EDGELESS_ANCHOR_LIMIT]:
        found = await _runtime._graph_store_call(
            graph_store.edges_for_node_ids, scan_id=scan_id, tenant_id=tenant, node_ids={node_id}, limit=1
        )
        if found:
            anchors[node_id] = found[0]
    unique: dict[int, Any] = {id(edge): edge for edge in anchors.values()}
    return list(unique.values())
