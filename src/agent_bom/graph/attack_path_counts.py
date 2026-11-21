"""The one attack-path count every surface reports: ``{retained_count, assessed_count, basis}``.

``retained_count`` is the attack-path queue's snapshot total: the snapshot's
path index (the ranked unique derived set, fusion rows included) when it has
one, else its persisted rows (``basis`` names which). ``assessed_count`` is what the
analyzers evaluated before deduplication, caps and exclusions: the fusion
pass's ``candidate_path_count`` plus every component-path candidate (served,
VEX-excluded or unlikely). When no analyzer recorded a candidate count it
equals ``retained_count``; it never falls below it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.graph.analysis import GraphAnalysisStatus
from agent_bom.graph.container import UnifiedGraph

PERSISTED = "persisted_graph_paths"
DERIVED = "derived_graph_paths"
_CANDIDATE_FIELDS = {
    "attack_path_fusion": ("candidate_path_count",),
    "component_paths": ("paths", "vex_excluded", "unlikely_excluded"),
}


def _observed(status: Any) -> Mapping[str, Any]:
    if isinstance(status, GraphAnalysisStatus):
        return status.observed
    observed = status.get("observed") if isinstance(status, Mapping) else None
    return observed if isinstance(observed, Mapping) else {}


def assessed_candidates(analysis_status: Mapping[str, Any] | None) -> int:
    total = 0
    for analyzer, fields in _CANDIDATE_FIELDS.items():
        observed = _observed((analysis_status or {}).get(analyzer))
        total += sum(int(value) for field in fields if isinstance(value := observed.get(field), int) and value > 0)
    return total


def attack_paths_summary(*, retained_count: int, basis: str, analysis_status: Mapping[str, Any] | None) -> dict[str, Any]:
    retained = max(int(retained_count), 0)
    return {
        "retained_count": retained,
        "assessed_count": max(assessed_candidates(analysis_status), retained),
        "basis": basis,
    }


def snapshot_attack_paths_summary(graph: UnifiedGraph) -> dict[str, Any]:
    """The summary the queue serves once this graph is saved with its path index.

    Counts the same materialized rows the store indexes, over detached copies so
    fusion rows stay as fusion wrote them; derivation stamps the candidates it assessed.
    """
    from agent_bom.graph.snapshot_paths import materialize_snapshot_paths

    rows = materialize_snapshot_paths(graph)
    return attack_paths_summary(retained_count=len(rows), basis=DERIVED, analysis_status=graph.analysis_status)


__all__ = ["DERIVED", "PERSISTED", "assessed_candidates", "attack_paths_summary", "snapshot_attack_paths_summary"]
