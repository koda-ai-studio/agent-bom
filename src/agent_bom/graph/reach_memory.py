"""Blast radius over an in-memory ``UnifiedGraph``, under the stores' reach policy.

The SQLite and Postgres stores walk through ``reach_walk``; this adapter gives
the in-memory graph the same walk so OCSF ``graph_context`` and every
in-memory caller report the radius the API reports for the same node.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from agent_bom.graph.completeness import impact_completeness
from agent_bom.graph.reach_view import WalkResult, reach_walk

if TYPE_CHECKING:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.edge import UnifiedEdge


def _steps(graph: UnifiedGraph, node_id: str, direction: str) -> Iterable[tuple[UnifiedEdge, str]]:
    if direction in {"in", "both"}:
        for edge in graph.reverse_adjacency.get(node_id, []):
            yield edge, edge.source
    if direction in {"out", "both"}:
        for edge in graph.adjacency.get(node_id, []):
            yield edge, edge.target


def _memory_walk(graph: UnifiedGraph) -> Callable[..., WalkResult]:
    def walk(*, roots: list[str], direction: str, max_depth: int, relationship_types: set[Any]) -> WalkResult:
        allowed = {getattr(rel, "value", rel) for rel in relationship_types}
        start = [root for root in roots if root in graph.nodes]
        depths = {root: 0 for root in start}
        queue = deque(start)
        depth_limited = False
        while queue:
            current = queue.popleft()
            for edge, neighbor in _steps(graph, current, direction):
                if neighbor in depths or getattr(edge.relationship, "value", edge.relationship) not in allowed:
                    continue
                if depths[current] >= max_depth:
                    depth_limited = True
                    continue
                depths[neighbor] = depths[current] + 1
                queue.append(neighbor)
        return (graph.scan_id, graph.created_at, set(depths), depths, {}, {}, list(depths), False, depth_limited)

    return walk


def in_memory_impact(graph: UnifiedGraph, node_id: str, max_depth: int = 4) -> dict[str, Any]:
    """The ``impact_of`` body for an in-memory graph: who can act on *node_id*."""
    node = graph.nodes.get(node_id)
    if node is None:
        return {"node_id": node_id, "affected_nodes": [], "affected_by_type": {}, "affected_count": 0, "max_depth_reached": 0}
    walk = reach_walk(_memory_walk(graph), root=node_id, root_type=node.entity_type, direction="in", max_depth=max_depth)
    affected = sorted(nid for nid in walk.visited if nid != node_id)
    by_type: dict[str, int] = {}
    for nid in affected:
        kind = str(getattr(graph.nodes[nid].entity_type, "value", graph.nodes[nid].entity_type))
        by_type[kind] = by_type.get(kind, 0) + 1
    return {
        "node_id": node_id,
        "affected_nodes": affected,
        "affected_by_type": by_type,
        "affected_count": len(affected),
        "max_depth_reached": max((walk.depth_by_node.get(nid, 0) for nid in affected), default=0),
        "completeness": impact_completeness(affected_count=len(affected), truncated=False, depth_limited=walk.depth_limited),
    }


__all__ = ["in_memory_impact"]
