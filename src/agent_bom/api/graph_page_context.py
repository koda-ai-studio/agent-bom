"""Resolve containment ancestors without reading a parent's entire estate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_bom.api.graph_page_stack import page_agent_stack
from agent_bom.graph import UnifiedEdge, UnifiedNode
from agent_bom.graph.rollup import ROLLUP_CONTAINMENT_RELATIONSHIPS

# Small pages keep their whole containment spine (the demo's 50-node canvas page
# carries ~260 context nodes); larger pages carry at most ``limit`` context nodes.
NODE_PAGE_CONTEXT_FLOOR = 500


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
    levels: dict[str, int] = {}
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
        levels.update(dict.fromkeys(parents, _level))
        frontier = parents
    if not ancestor_ids:
        return [], []
    nodes = await call_store(graph_store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=ancestor_ids)
    # Nearest parents first, so a context cap cuts the farthest ancestors.
    ordered = sorted(nodes, key=lambda node: (levels.get(node.id, 5), node.id))
    return ordered, list(ancestor_edges.values())


def node_page_context_limit(limit: int) -> int:
    """Most stack and containment nodes one ``/v1/graph`` page carries beside its ranked slice."""
    return max(limit, NODE_PAGE_CONTEXT_FLOOR)


@dataclass(frozen=True)
class PageContext:
    nodes: list[UnifiedNode]
    edges: list[UnifiedEdge]
    stack: dict[str, Any]
    endpoints: list[UnifiedNode]
    limit: int
    omitted: int


async def page_context(
    graph_store: Any,
    *,
    scan_id: str,
    tenant_id: str,
    page_nodes: list[UnifiedNode],
    call_store: Any,
    page_edges: list[UnifiedEdge] = (),  # type: ignore[assignment]
    context_limit: int | None = None,
) -> PageContext:
    """Context for a ranked page: the agent stack, containment above page and stack, then edge endpoints.

    Stack and containment nodes are capped at ``context_limit`` (stack first,
    then nearest ancestors); a context edge whose end was cut is dropped with
    it. The off-page endpoints of every remaining edge follow, bounded by the
    incident-edge slice, so no edge in the payload points at a node the client
    never received.
    """
    stack = await page_agent_stack(graph_store, scan_id=scan_id, tenant_id=tenant_id, page_nodes=page_nodes, call_store=call_store)
    ranked_ids = {node.id for node in page_nodes}
    page_ids = ranked_ids | {node.id for node in stack.nodes}
    ancestors, ancestor_edges = await containment_ancestors(
        graph_store, scan_id=scan_id, tenant_id=tenant_id, node_ids=page_ids, call_store=call_store
    )
    context = [*stack.nodes, *ancestors]
    cap = len(context) if context_limit is None else context_limit
    kept = context[:cap]
    cut = {node.id for node in context[cap:]}
    context_edges = [edge for edge in [*stack.edges, *ancestor_edges] if edge.source not in cut and edge.target not in cut]
    present = ranked_ids | {node.id for node in kept}
    missing = {end for edge in [*page_edges, *context_edges] for end in (edge.source, edge.target)} - present
    endpoints = await call_store(graph_store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=missing) if missing else []
    return PageContext(
        nodes=kept,
        edges=context_edges,
        stack=stack.summary(),
        endpoints=sorted(endpoints, key=lambda node: node.id),
        limit=cap,
        omitted=len(context) - len(kept),
    )


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
