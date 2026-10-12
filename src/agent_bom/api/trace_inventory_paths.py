"""Bounded inventory paths from an exact trace identity claim, never execution proof."""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from agent_bom.graph import EntityType, RelationshipType, UnifiedGraph

_RELATIONSHIPS = {RelationshipType.USES, RelationshipType.DEPENDS_ON, RelationshipType.CONTAINS, RelationshipType.VULNERABLE_TO}


def _finding_paths(graph: UnifiedGraph, root: str) -> tuple[list[dict[str, Any]], bool]:
    pending: deque[tuple[list[str], list[str]]] = deque([([root], [])])
    seen = {root}
    paths: list[dict[str, Any]] = []
    while pending and len(paths) < 10:
        nodes, edges = pending.popleft()
        node = graph.nodes.get(nodes[-1])
        if node and node.entity_type == EntityType.VULNERABILITY:
            paths.append(
                {
                    "basis": "recorded_inventory_relationships",
                    "execution_proven": False,
                    "node_ids": nodes,
                    "edge_ids": edges,
                    "node_labels": [graph.nodes[identity].label for identity in nodes],
                    "finding_node_id": node.id,
                }
            )
            continue
        if len(edges) >= 4:
            continue
        for edge in sorted(graph.edges_from(nodes[-1]), key=lambda item: item.id):
            if edge.target in seen or edge.target not in graph.nodes or edge.relationship not in _RELATIONSHIPS:
                continue
            seen.add(edge.target)
            pending.append(([*nodes, edge.target], [*edges, edge.id]))
    return paths, bool(pending)


def attach_inventory_paths(store: Any, *, tenant_id: str, scan_id: str, bindings: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    exact = {key: row for key, row in bindings.items() if row.get("state") == "exact_identifier"}
    if not exact:
        return bindings
    generation = store.snapshot_identity(tenant_id=tenant_id, scan_id=scan_id)
    if any((row.get("scan_id"), row.get("snapshot_generation")) != generation for row in exact.values()):
        return {key: {"state": "snapshot_changed", "execution_proven": False} if key in exact else row for key, row in bindings.items()}
    graph, _, truncated = store.traverse_subgraph(
        tenant_id=tenant_id,
        scan_id=scan_id,
        roots=sorted({row["node_id"] for row in exact.values()}),
        direction="forward",
        max_depth=4,
        max_nodes=500,
        max_edges=1000,
        relationship_types=_RELATIONSHIPS,
        deadline_monotonic=time.monotonic() + 0.5,
    )
    paths = {row["node_id"]: _finding_paths(graph, row["node_id"]) for row in exact.values()}
    if store.snapshot_identity(tenant_id=tenant_id, scan_id=scan_id) != generation:
        return {key: {"state": "snapshot_changed", "execution_proven": False} if key in exact else row for key, row in bindings.items()}
    return {
        key: {
            **row,
            "inventory_paths": paths[row["node_id"]][0],
            "paths_scope": "bounded_recorded_inventory",
            "paths_truncated": truncated or graph.completeness.depth_limited or paths[row["node_id"]][1],
        }
        if key in exact
        else row
        for key, row in bindings.items()
    }
