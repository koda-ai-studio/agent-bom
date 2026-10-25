"""Copy canonical unified-graph nodes and relationships into a dependency-graph export."""

from __future__ import annotations

from typing import Any

from agent_bom.graph import UnifiedGraph


def merge_unified_graph(graph: Any, unified: UnifiedGraph) -> None:
    """Add every unified node the export lacks, then every relationship whose endpoints it holds."""
    for node in unified.nodes.values():
        if graph._nodes.get(node.id) is not None:
            continue
        etype = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
        graph.add_node(
            node.id,
            node.label or node.id,
            etype,
            severity=str(getattr(node, "severity", "") or ""),
            attributes=dict(node.attributes or {}),
        )
    edges = unified.edges.values() if isinstance(unified.edges, dict) else unified.edges
    for edge in edges:
        rel = edge.relationship.value if hasattr(edge.relationship, "value") else str(edge.relationship)
        if edge.source in graph._nodes and edge.target in graph._nodes and not graph.has_relationship(edge.source, edge.target, rel):
            graph.add_edge(edge.source, edge.target, rel, evidence=dict(getattr(edge, "evidence", {}) or {}))
