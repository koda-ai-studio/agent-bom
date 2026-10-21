"""Fail closed for traversal through observations with contradictory owner scope."""

from agent_bom.graph.asset_identity import cloud_identity_scope, family_of
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge


def guard_cloud_identity_scope(graph: UnifiedGraph) -> int:
    """Preserve inventory and edges as evidence, but do not route through conflicts."""
    from agent_bom.graph.store_backed import StoreBackedUnifiedGraph

    conflicted: set[str] = set()
    for node in graph.nodes.values():
        if not family_of(node):
            continue
        scope = cloud_identity_scope(node)
        if scope["status"] == "conflict":
            node.attributes["identity_scope"] = scope
            conflicted.add(node.id)
    if not conflicted:
        return 0
    pending: list[UnifiedEdge] = []
    for edge in graph.edges:
        if edge.source not in conflicted and edge.target not in conflicted:
            continue
        edge.traversable = False
        edge.evidence["identity_scope_status"] = "conflict"
        if isinstance(graph, StoreBackedUnifiedGraph):
            pending.append(edge)
            if len(pending) >= 500:
                graph.write_edges(pending)
                pending.clear()
    if isinstance(graph, StoreBackedUnifiedGraph):
        if pending:
            graph.write_edges(pending)
    else:
        # Bidirectional reverse adjacency holds separate edge objects.
        for node_id in conflicted:
            for edge in (*graph.edges_from(node_id), *graph.edges_to(node_id)):
                edge.traversable = False
                edge.evidence["identity_scope_status"] = "conflict"
    return len(conflicted)
