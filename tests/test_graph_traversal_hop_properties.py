"""Traversal hop counts match a reference BFS on cyclic graphs, in memory and in the store.

Hop counts drive "N hops away" labels, depth limits and blast-radius ordering.
Each backend must agree with a plain shortest-path BFS for every direction,
terminate on cycles, never cross a depth bound, and never read another
tenant's edges.
"""

from __future__ import annotations

import random
from collections import deque

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def _random_graph(seed: int, tenant: str) -> UnifiedGraph:
    rng = random.Random(seed)
    graph = UnifiedGraph(scan_id=f"hops-{seed}", tenant_id=tenant)
    ids = [f"n{i}" for i in range(30)]
    for node_id in ids:
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.SERVER, label=node_id))
    for _ in range(60):
        source, target = rng.sample(ids, 2)
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.DEPENDS_ON))
    return graph


def _reference(graph: UnifiedGraph, root: str, direction: str, max_depth: int) -> dict[str, int]:
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for edge in graph.edges:
        forward.setdefault(edge.source, set()).add(edge.target)
        reverse.setdefault(edge.target, set()).add(edge.source)
    depth = {root: 0}
    queue = deque([root])
    while queue:
        current = queue.popleft()
        if depth[current] >= max_depth:
            continue
        neighbors: set[str] = set()
        if direction in {"forward", "both"}:
            neighbors |= forward.get(current, set())
        if direction in {"reverse", "both"}:
            neighbors |= reverse.get(current, set())
        for neighbor in sorted(neighbors):
            if neighbor not in depth:
                depth[neighbor] = depth[current] + 1
                queue.append(neighbor)
    return depth


@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize("direction", ["forward", "reverse", "both"])
def test_hop_counts_match_reference_bfs_in_memory_and_store(tmp_path, seed: int, direction: str) -> None:
    graph = _random_graph(seed, "tenant-a")
    # A second tenant with the same node ids and a shortcut edge must never leak in.
    other = _random_graph(seed, "tenant-b")
    other.add_edge(UnifiedEdge(source="n0", target="n29", relationship=RelationshipType.DEPENDS_ON))
    other.add_edge(UnifiedEdge(source="n29", target="n0", relationship=RelationshipType.DEPENDS_ON))
    store = SQLiteGraphStore(tmp_path / "hops.db")
    store.save_graph(graph)
    store.save_graph(other)
    for max_depth in (1, 2, 4):
        expected = _reference(graph, "n0", direction, max_depth)
        _sub, memory_depths, memory_truncated = graph.traverse_subgraph(["n0"], direction=direction, max_depth=max_depth, max_nodes=10_000)
        stored, store_depths, store_truncated = store.traverse_subgraph(
            tenant_id="tenant-a", scan_id=graph.scan_id, roots=["n0"], direction=direction, max_depth=max_depth, max_nodes=10_000
        )
        assert memory_depths == expected
        assert store_depths == expected
        assert not memory_truncated and not store_truncated
        assert max(expected.values()) <= max_depth
        assert set(stored.nodes) == set(expected)
        assert stored.tenant_id == "tenant-a"
