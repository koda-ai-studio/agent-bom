"""The roll-up aggregate a scope carries, and how the returned scopes reconcile.

Split from :mod:`agent_bom.graph.rollup` so the view module stays a walk over
the containment tree; the shapes here are what every roll-up entry reports.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_bom.core.severity import SEVERITY_BUCKETS_WORST_FIRST
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.rollup_issues import ISSUE_SEVERITY_BASIS, ISSUE_SEVERITY_DEFINITION

_SEVERITY_ORDER: tuple[str, ...] = SEVERITY_BUCKETS_WORST_FIRST


@dataclass(slots=True)
class RollupAggregate:
    """Aggregate risk facts rolled up from a container's descendants."""

    descendant_count: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    # Distinct open finding issues (the overview's basis), not rated nodes.
    severity_counts: dict[str, int] = field(default_factory=dict)
    # Every descendant node's own rating, rated assets included.
    node_severity_counts: dict[str, int] = field(default_factory=dict)
    issue_count: int = 0
    finding_occurrence_count: int = 0
    worst_severity: str = "none"
    worst_severity_rank: int = 0
    internet_exposed: bool = False
    toxic_combo: bool = False
    exposed_count: int = 0
    toxic_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "descendant_count": self.descendant_count,
            "by_type": dict(sorted(self.by_type.items())),
            "severity_counts": _histogram(self.severity_counts),
            "issue_count": self.issue_count,
            "finding_occurrence_count": self.finding_occurrence_count,
            "worst_severity": self.worst_severity,
            "worst_severity_rank": self.worst_severity_rank,
            "internet_exposed": self.internet_exposed,
            "toxic_combo": self.toxic_combo,
            "exposed_count": self.exposed_count,
            "toxic_count": self.toxic_count,
        }


def _histogram(counts: dict[str, int]) -> dict[str, int]:
    return {sev: counts.get(sev, 0) for sev in _SEVERITY_ORDER}


def aggregate_count_metadata(graph: UnifiedGraph, memberships: Counter[str], occurrences: Optional[Counter[str]] = None) -> dict[str, Any]:
    """Reconcile the returned entries' aggregates without assuming disjoint scopes.

    Each aggregate counts a descendant once within that entry. A DAG can put
    the same descendant in several entries; summing them counts memberships,
    not unique assets. Collect during the existing aggregation walk so this
    does not introduce a second traversal or return unbounded member IDs.
    """
    membership_count = sum(memberships.values())
    distinct_count = len(memberships)
    occurrences = occurrences if occurrences is not None else Counter()
    occurrence_memberships = sum(occurrences.values())
    return {
        "basis": "returned_entry_descendants",
        "definition": "Filtered descendants of returned entries, excluding each entry itself; not an estate total.",
        "distinct_descendants": distinct_count,
        "descendant_memberships": membership_count,
        "shared_descendants": sum(count > 1 for count in memberships.values()),
        "extra_memberships": membership_count - distinct_count,
        "additive": membership_count == distinct_count,
        # The same reconciliation for finding occurrences: an occurrence on a
        # server two agents use is in both agents' counts, once in the estate.
        "distinct_finding_occurrences": len(occurrences),
        "finding_occurrence_memberships": occurrence_memberships,
        "occurrences_additive": occurrence_memberships == len(occurrences),
        "severity_basis": ISSUE_SEVERITY_BASIS,
        "severity_definition": ISSUE_SEVERITY_DEFINITION,
        "source_truncated": graph.completeness.truncated,
        "reason": graph.completeness.reason if graph.completeness.truncated else "",
    }


__all__ = ["RollupAggregate", "_histogram", "aggregate_count_metadata"]
