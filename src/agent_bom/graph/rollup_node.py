"""One node's roll-up aggregate, computed exactly as its roll-up entry's."""

from __future__ import annotations

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.rollup import _aggregate, _contains_children, _descendants, _node_facts
from agent_bom.graph.rollup_aggregate import RollupAggregate
from agent_bom.graph.rollup_issues import build_finding_index


def node_aggregate(graph: UnifiedGraph, node_id: str, *, suppressed_finding_ids: frozenset[str] = frozenset()) -> RollupAggregate | None:
    """The aggregate *node_id*'s own roll-up entry carries: its containment subtree, scoped to it."""
    if node_id not in graph.nodes:
        return None
    facts = _node_facts(graph, suppressed_finding_ids)
    return _aggregate(_descendants(node_id, _contains_children(graph)), graph, facts=facts, scope_root=node_id)


def scope_findings(graph: UnifiedGraph, node_id: str, *, suppressed: frozenset[str] = frozenset()) -> list[dict]:
    """Disclose the exact issue groups counted by node_aggregate, retaining original node ids."""
    if node_id not in graph.nodes:
        return []
    scope = {node_id, *_descendants(node_id, _contains_children(graph))}
    groups: dict[str, dict] = {}
    for finding_id, facts in build_finding_index(graph, suppressed).items():
        if finding_id not in scope:
            continue
        issues, occurrences = facts.scoped(scope)
        if not occurrences:
            continue
        node = graph.nodes[finding_id]
        for key in issues:
            row = groups.setdefault(key, {"issue_key": key, "label": node.label, "severity": node.severity, "node_ids": []})
            row["node_ids"].append(finding_id)
            if SEVERITY_RANK.get(node.severity, 0) > SEVERITY_RANK.get(row["severity"], 0):
                row["severity"] = node.severity
    for row in groups.values():
        row["node_ids"].sort()
    return sorted(groups.values(), key=lambda row: (-SEVERITY_RANK.get(row["severity"], 0), row["issue_key"]))


__all__ = ["node_aggregate", "scope_findings"]
