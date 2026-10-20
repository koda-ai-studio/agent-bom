"""Resolve containment ancestors without reading a parent's entire estate."""

from __future__ import annotations

from typing import Any

from agent_bom.api.graph_page_stack import page_agent_stack
from agent_bom.graph import UnifiedEdge, UnifiedNode
from agent_bom.graph.rollup import ROLLUP_CONTAINMENT_RELATIONSHIPS


async def containment_ancestors(
    graph_store: Any,
    *,
    scan_id: str,
    tenant_id: str,
    node_ids: set[str],
    call_store: Any,
) -> tuple[list[UnifiedNode], list[UnifiedEdge]]:
    """Follow incoming containment edges for at most five parent levels.

    Ranked findings often exclude the account/environment spine. Read that
    context separately from bounded incident evidence so an omitted relationship
    cannot erase a parent. Outgoing siblings never need to be hydrated.
    """
    ancestor_ids: set[str] = set()
    ancestor_edges: dict[tuple[str, str], UnifiedEdge] = {}
    frontier = set(node_ids)
    for _level in range(5):
        if not frontier:
            break
        edges = await call_store(
            graph_store.edges_for_node_ids,
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_ids=frontier,
            direction="in",
            relationships=set(ROLLUP_CONTAINMENT_RELATIONSHIPS),
        )
        parents = set()
        for edge in edges:
            if edge.target in frontier and edge.source not in node_ids:
                parents.add(edge.source)
                ancestor_edges[(edge.source, edge.target)] = edge
        parents -= ancestor_ids
        ancestor_ids |= parents
        frontier = parents
    if not ancestor_ids:
        return [], []
    nodes = await call_store(graph_store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=ancestor_ids)
    return list(nodes), list(ancestor_edges.values())


async def page_context(
    graph_store: Any, *, scan_id: str, tenant_id: str, page_nodes: list[UnifiedNode], call_store: Any
) -> tuple[list[UnifiedNode], list[UnifiedEdge], dict[str, Any]]:
    """Context nodes/edges for a ranked page: the agent stack, then containment above page and stack.

    Returns the context nodes and edges plus the stack's completeness summary.
    """
    stack = await page_agent_stack(graph_store, scan_id=scan_id, tenant_id=tenant_id, page_nodes=page_nodes, call_store=call_store)
    page_ids = {node.id for node in page_nodes} | {node.id for node in stack.nodes}
    nodes, edges = await containment_ancestors(graph_store, scan_id=scan_id, tenant_id=tenant_id, node_ids=page_ids, call_store=call_store)
    return [*stack.nodes, *nodes], [*stack.edges, *edges], stack.summary()


async def page_attack_context(
    graph_store: Any, *, scan_id: str, tenant_id: str, node_ids: set[str], call_store: Any
) -> tuple[list[Any], list[UnifiedNode]]:
    """Read path records and their supplemental hop nodes off the event loop.

    A snapshot with a current path index serves its complete ranked set, so the
    page agrees with ``/v1/graph/attack-paths``; older snapshots keep reading
    the fusion rows they were written with.
    """
    stored = None
    if getattr(graph_store, "snapshot_attack_paths", None) is not None:
        stored = await call_store(graph_store.snapshot_attack_paths, scan_id=scan_id, tenant_id=tenant_id, source_ids=node_ids)
    if stored is not None:
        paths = list(stored.paths)
    else:
        paths = await call_store(graph_store.attack_paths_for_sources, scan_id=scan_id, tenant_id=tenant_id, source_ids=node_ids)
    hop_ids = {hop for path in paths for hop in path.hops}
    nodes = await call_store(graph_store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=hop_ids - node_ids)
    return paths, nodes
