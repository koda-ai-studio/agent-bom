"""Canonical read-only consequence orchestration with an injected clock."""

from __future__ import annotations

import time
from datetime import datetime

from agent_bom.graph.consequence.contracts import ConsequenceAssessment, ConsequenceRequest, Frontier
from agent_bom.graph.consequence.prerequisites import starting_state
from agent_bom.graph.consequence.projection import count_consequences, reconcile_denials
from agent_bom.graph.consequence.traversal import Walk, traverse
from agent_bom.graph.container import UnifiedGraph


def assess_consequences(
    graph: UnifiedGraph, request: ConsequenceRequest, *, tenant_id: str, at: datetime, deadline_monotonic: float | None = None
) -> ConsequenceAssessment:
    if not tenant_id or tenant_id != graph.tenant_id:
        raise ValueError("assessment tenant mismatch")
    if not graph.scan_id or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("snapshot identity and timezone-aware evaluation time required")
    root, prerequisites = starting_state(graph, request)
    if prerequisites.status in {"unknown", "blocked"}:
        walk = Walk(
            frontier=[
                Frontier(
                    node_ids=[request.root_node_id, root],
                    edge_ids=[],
                    reason_codes=prerequisites.reason_codes,
                    next_collection_step=(
                        "Collect occurrence-specific deployed version/configuration, entry point and exploit prerequisites."
                    ),
                )
            ]
        )
    else:
        walk = traverse(graph, root, request, at, deadline=deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 2.5)
    reasons = sorted(walk.reasons | {"estate_coverage_unknown", "session_and_exploitability_producers_unqualified"})
    walk.consequences = reconcile_denials(walk.consequences)
    walk.consequences = [
        item.model_copy(
            update={
                "node_labels": [graph.nodes[node].label if node in graph.nodes else node for node in item.node_ids],
                "node_types": [graph.nodes[node].entity_type.value if node in graph.nodes else "unknown" for node in item.node_ids],
            }
        )
        for item in walk.consequences
    ]
    counts = count_consequences(walk.consequences, truncated=walk.truncated)
    # Frontier counts are separate from action/resource counts: a missing
    # session does not invent a target consequence. Both remain in one receipt.
    return ConsequenceAssessment(
        tenant_id=tenant_id,
        scan_id=graph.scan_id,
        assessed_at=at.isoformat(),
        request=request,
        affected_node_id=request.affected_node_id,
        prerequisites=prerequisites,
        counts=counts,
        states_examined=walk.states_examined,
        truncated=walk.truncated,
        reason_codes=reasons,
        consequences=walk.consequences,
        frontier=walk.frontier,
    )
