"""Prioritize recorded fix guidance by marginal path coverage, without simulating a fix."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.attack_path_queue_rank import PATH_FAMILY_TRACE, path_family
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.exposure import exposure_path_id
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

MAX_PATHS = 5_000
MAX_HOPS = 32
MAX_RECOMMENDATIONS = 5
MAX_CANDIDATES = 1_000
PATH_SAMPLE = 5
_FINDINGS = {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}


@dataclass
class _Candidate:
    details: dict[str, Any]
    paths: set[str] = field(default_factory=set)
    critical: set[str] = field(default_factory=set)
    high: set[str] = field(default_factory=set)
    unknown: set[str] = field(default_factory=set)


def _guidance(graph: UnifiedGraph, asset_id: str, finding_id: str) -> dict[str, Any] | None:
    asset, finding = graph.nodes[asset_id], graph.nodes[finding_id]
    fixed = finding.attributes.get("fixed_version")
    fixed = sanitize_text(fixed.strip(), max_len=128) if isinstance(fixed, str) else ""
    recorded = finding.attributes.get("remediation") or finding.attributes.get("recommendation")
    recorded = sanitize_text(recorded.strip(), max_len=2000) if isinstance(recorded, str) else ""
    if asset.entity_type == EntityType.PACKAGE and finding.entity_type == EntityType.VULNERABILITY and fixed:
        guidance = (
            f"Review upgrading {sanitize_text(asset.label, max_len=512)} to {fixed}. "
            "Confirm applicability and compatibility before changing it."
        )
    elif recorded:
        guidance = recorded
        fixed = ""
    else:
        return None
    identity = hashlib.sha256(f"{asset_id}\0{finding_id}\0{guidance}".encode()).hexdigest()[:24]
    return {
        "id": identity,
        "asset_node_id": asset_id,
        "asset_label": sanitize_text(asset.label, max_len=512),
        "finding_node_id": finding_id,
        "finding_label": sanitize_text(finding.label, max_len=512),
        "finding_id": str(finding.attributes.get("finding_id") or ""),
        "fixed_version": fixed or None,
        "guidance": guidance,
    }


def _collect(
    graph: UnifiedGraph,
    paths: list[AttackPath],
    limitations: set[str],
) -> tuple[dict[str, _Candidate], set[str]]:
    # Only a recorded, direct affected-asset relationship can bind guidance to
    # an asset. Co-occurrence elsewhere in a path must not imply applicability.
    bound = {(edge.source, edge.target) for edge in graph.edges if edge.relationship == RelationshipType.VULNERABLE_TO}
    candidates: dict[str, _Candidate] = {}
    assessed: set[str] = set()
    for path in paths[:MAX_PATHS]:
        if len(path.hops) > MAX_HOPS:
            limitations.add("hop_budget")
            continue
        path_id = exposure_path_id(path)
        if path_id in assessed:
            continue
        assessed.add(path_id)
        if any(hop not in graph.nodes for hop in path.hops):
            limitations.add("path_nodes_unavailable")
            continue
        if path_family(path) == PATH_FAMILY_TRACE or path.reachability == "unlikely":
            continue
        for asset_id, finding_id in zip(path.hops, path.hops[1:]):
            if (asset_id, finding_id) not in bound or graph.nodes[finding_id].entity_type not in _FINDINGS:
                continue
            guidance = _guidance(graph, asset_id, finding_id)
            if guidance is None:
                continue
            if guidance["id"] not in candidates and len(candidates) >= MAX_CANDIDATES:
                limitations.add("candidate_budget")
                continue
            candidate = candidates.setdefault(guidance["id"], _Candidate(guidance))
            candidate.paths.add(path_id)
            severity = str(graph.nodes[finding_id].severity or "").lower()
            if severity == "critical":
                candidate.critical.add(path_id)
            elif severity == "high":
                candidate.high.add(path_id)
            if path.reachability not in {"confirmed", "likely"}:
                candidate.unknown.add(path_id)
    return candidates, assessed


def _rank(candidates: dict[str, _Candidate], assessed: set[str]) -> tuple[list[dict[str, Any]], set[str]]:
    covered: set[str] = set()
    rows: list[dict[str, Any]] = []
    remaining = dict(candidates)
    while remaining and len(rows) < MAX_RECOMMENDATIONS:
        identity = min(
            remaining,
            key=lambda key: (
                -len(remaining[key].critical - covered),
                -len(remaining[key].high - covered),
                -len(remaining[key].paths - covered),
                -len(remaining[key].paths),
                key,
            ),
        )
        candidate = remaining.pop(identity)
        marginal = candidate.paths - covered
        covered.update(candidate.paths)
        rows.append(
            {
                **candidate.details,
                "rank": len(rows) + 1,
                "covered_paths": len(candidate.paths),
                "newly_covered_paths": len(marginal),
                "critical_paths": len(candidate.critical),
                "high_paths": len(candidate.high),
                "unknown_reachability_paths": len(candidate.unknown),
                "remaining_paths_after_selection": len(assessed - covered),
                "path_ids": sorted(candidate.paths)[:PATH_SAMPLE],
                "path_sample_complete": len(candidate.paths) <= PATH_SAMPLE,
            }
        )
    return rows, covered


def remediation_priorities(graph: UnifiedGraph, paths: list[AttackPath]) -> dict[str, Any]:
    """Greedy marginal coverage over a bounded recorded path population.

    Coverage means that a path touches a directly bound finding with recorded
    guidance. It is neither a counterfactual path removal nor an effectiveness
    prediction. Alternate paths and uncollected evidence remain unverified.
    """
    limitations: set[str] = set()
    if len(paths) > MAX_PATHS:
        limitations.add("path_budget")
    if graph.completeness.truncated or graph.completeness.depth_limited:
        limitations.add(graph.completeness.reason or "graph_incomplete")
    for status in graph.analysis_status.values():
        if str(getattr(status.status, "value", status.status)) != "complete":
            limitations.add("analysis_incomplete")
    candidates, assessed = _collect(graph, paths, limitations)
    recommendations, covered = _rank(candidates, assessed)
    return {
        "schema_version": "graph-remediation-priorities.v1",
        "coverage_basis": "recorded_paths_touching_selected_findings",
        "source_coverage": "not_assessed",
        "method": "greedy_marginal_critical_then_high_then_all_path_coverage",
        "assessed_paths": len(assessed),
        "candidate_count": len(candidates),
        "covered_paths": len(covered),
        "remaining_paths": len(assessed - covered),
        "complete": not limitations,
        "limitations": sorted(limitations),
        "path_budget": MAX_PATHS,
        "recommendation_limit": MAX_RECOMMENDATIONS,
        "remediation_verified": False,
        "recommendations": recommendations,
    }
