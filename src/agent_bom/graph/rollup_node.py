"""One node's roll-up aggregate, computed exactly as its roll-up entry's."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.rollup import _aggregate, _contains_children, _descendants, _node_facts
from agent_bom.graph.rollup_aggregate import RollupAggregate


def node_aggregate(graph: UnifiedGraph, node_id: str, *, suppressed_finding_ids: frozenset[str] = frozenset()) -> RollupAggregate | None:
    """The aggregate *node_id*'s own roll-up entry carries: its containment subtree, scoped to it."""
    if node_id not in graph.nodes:
        return None
    facts = _node_facts(graph, suppressed_finding_ids)
    return _aggregate(_descendants(node_id, _contains_children(graph)), graph, facts=facts, scope_root=node_id)


__all__ = ["node_aggregate"]
