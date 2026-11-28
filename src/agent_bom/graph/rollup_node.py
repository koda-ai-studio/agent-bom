"""One node's roll-up aggregate, computed exactly as its roll-up entry's."""

from __future__ import annotations

from collections import Counter

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.rollup import _aggregate, _contains_children, _descendants, _node_facts
from agent_bom.graph.rollup_aggregate import RollupAggregate


class ScopeIndex:
    """Containment and finding facts for one graph, derived once and shared by every scope read on it.

    A selected path asks about several nested scopes of the same graph. Each
    question walks only its own subtree; the whole-graph passes (edge
    classification, finding identities) run once per graph, not once per scope.
    """

    def __init__(self, graph: UnifiedGraph, suppressed: frozenset[str] = frozenset()) -> None:
        self.graph = graph
        self.suppressed = suppressed
        self._children: dict[str, list[str]] | None = None
        self._facts: dict | None = None
        self._descendants: dict[str, list[str]] = {}
        self._descendant_sets: dict[str, frozenset[str]] = {}
        self._groups: dict[str, dict[str, dict]] = {}
        self._position: dict[str, int] | None = None

    @property
    def children(self) -> dict[str, list[str]]:
        if self._children is None:
            self._children = _contains_children(self.graph)
        return self._children

    @property
    def facts(self) -> dict:
        if self._facts is None:
            self._facts = _node_facts(self.graph, self.suppressed)
        return self._facts

    def descendants(self, node_id: str) -> list[str]:
        if node_id not in self._descendants:
            self._descendants[node_id] = _descendants(node_id, self.children)
        return self._descendants[node_id]

    def descendant_set(self, node_id: str) -> frozenset[str]:
        if node_id not in self._descendant_sets:
            self._descendant_sets[node_id] = frozenset(self.descendants(node_id))
        return self._descendant_sets[node_id]

    def aggregate(self, node_id: str) -> RollupAggregate | None:
        if node_id not in self.graph.nodes:
            return None
        return _aggregate(self.descendants(node_id), self.graph, facts=self.facts, scope_root=node_id)

    def _issue_groups(self, node_id: str) -> dict[str, dict]:
        """Issue key -> disclosure row for the open findings in *node_id*'s scope."""
        if node_id in self._groups:
            return self._groups[node_id]
        scope = self.descendant_set(node_id) | {node_id}
        if self._position is None:
            self._position = {nid: index for index, nid in enumerate(self.graph.nodes)}
        position = self._position
        # Graph order, so a group's label is the first finding the graph holds for it.
        members = sorted((nid for nid in scope if nid in position), key=position.__getitem__)
        groups: dict[str, dict] = {}
        for finding_id in members:
            fact = self.facts.get(finding_id)
            finding = fact[5] if fact is not None else None
            if finding is None:
                continue
            issues, occurrences = finding.scoped(scope)
            if not occurrences:
                continue
            node = self.graph.nodes[finding_id]
            for key in issues:
                row = groups.setdefault(key, {"issue_key": key, "label": node.label, "severity": node.severity, "node_ids": []})
                row["node_ids"].append(finding_id)
                if SEVERITY_RANK.get(node.severity, 0) > SEVERITY_RANK.get(row["severity"], 0):
                    row["severity"] = node.severity
        self._groups[node_id] = groups
        return groups

    def findings(self, node_id: str, exclude_node_ids: tuple[str, ...] = ()) -> list[dict]:
        """Disclose the exact issue groups counted by the aggregate, retaining original node ids."""
        if node_id not in self.graph.nodes:
            return []
        groups = self._issue_groups(node_id)
        excluded = {key for child in exclude_node_ids if child in self.graph.nodes for key in self._issue_groups(child)}
        rows = [{**row, "node_ids": sorted(row["node_ids"])} for key, row in groups.items() if key not in excluded]
        return sorted(rows, key=lambda row: (-SEVERITY_RANK.get(row["severity"], 0), row["issue_key"]))

    def disclosure(self, node_id: str, exclude_node_ids: tuple[str, ...] = ()) -> dict:
        """Count and severity mix of the disclosed issues, without building their row lists."""
        groups = self._issue_groups(node_id) if node_id in self.graph.nodes else {}
        excluded = {key for child in exclude_node_ids if child in self.graph.nodes for key in self._issue_groups(child)}
        kept = [row for key, row in groups.items() if key not in excluded]
        return {
            "issue_count": len(kept),
            "severity_counts": dict(Counter(row["severity"] for row in kept)),
            "exclude_node_ids": list(exclude_node_ids),
        }


def node_aggregate(graph: UnifiedGraph, node_id: str, *, suppressed_finding_ids: frozenset[str] = frozenset()) -> RollupAggregate | None:
    """The aggregate *node_id*'s own roll-up entry carries: its containment subtree, scoped to it."""
    return ScopeIndex(graph, suppressed_finding_ids).aggregate(node_id)


def scope_findings(
    graph: UnifiedGraph, node_id: str, *, suppressed: frozenset[str] = frozenset(), exclude_node_ids: tuple[str, ...] = ()
) -> list[dict]:
    """Disclose the exact issue groups counted by node_aggregate, retaining original node ids."""
    return ScopeIndex(graph, suppressed).findings(node_id, exclude_node_ids)


__all__ = ["ScopeIndex", "node_aggregate", "scope_findings"]
