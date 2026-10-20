"""The ``/v1/graph`` node page's incident edges, bounded, with no ranked node left edgeless."""

from __future__ import annotations

from typing import Any

from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes.payloads import _NODE_PAGE_EDGE_LIMIT

# At most this many ranked nodes are re-anchored when the edge budget leaves them edgeless.
_EDGELESS_ANCHOR_LIMIT = 50


async def _page_edges(graph_store: Any, *, scan_id: str, tenant: str, node_ids: set[str]) -> tuple[list[Any], bool]:
    """The page's incident edges within budget, plus one anchor for any ranked node it left edgeless."""
    edges = await _runtime._graph_store_call(
        graph_store.edges_for_node_ids, scan_id=scan_id, tenant_id=tenant, node_ids=node_ids, limit=_NODE_PAGE_EDGE_LIMIT + 1
    )
    truncated = len(edges) > _NODE_PAGE_EDGE_LIMIT
    edges = edges[:_NODE_PAGE_EDGE_LIMIT]
    if truncated:
        anchors = await _anchor_edgeless_nodes(graph_store, scan_id=scan_id, tenant=tenant, node_ids=node_ids, edges=edges)
        # Anchors take the budget's tail slots: the page never exceeds its edge limit.
        edges = [*edges[: _NODE_PAGE_EDGE_LIMIT - len(anchors)], *anchors]
    return edges, truncated


async def _anchor_edgeless_nodes(graph_store: Any, *, scan_id: str, tenant: str, node_ids: set[str], edges: list[Any]) -> list[Any]:
    """One edge for each ranked node the truncated edge budget left with none.

    A hub (one advisory held by dozens of packages) can sort every incident
    edge past the budget and render as an orphan; a holder edge keeps it anchored.
    """
    touched = {edge.source for edge in edges} | {edge.target for edge in edges}
    anchors: list[Any] = []
    for node_id in sorted(node_ids - touched)[:_EDGELESS_ANCHOR_LIMIT]:
        for direction in ("in", "both"):
            found = await _runtime._graph_store_call(
                graph_store.edges_for_node_ids, scan_id=scan_id, tenant_id=tenant, node_ids={node_id}, direction=direction, limit=1
            )
            if found:
                anchors.extend(found)
                break
    return anchors
