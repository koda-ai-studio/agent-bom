"""Exploitability-evidence ranking for the attack-path queue.

Persisted paths come from several producers whose ``composite_risk`` values sit
on different scales, and hop-evidence qualification deliberately caps
structural candidates. Sorting by the stored score alone therefore let a
correlated trace with no finding, credential, or fix outrank an agent reaching
a KEV through a credential-bearing server. The queue orders by what is on the
path first and uses the stored score only inside an evidence tier.

``graph_reachable`` follows the repository's inbound definition: a finding is
graph-reachable when ANY attack path reaches it, and a path whose entrypoint is
an agent is the stronger signal. It is distinct from ``reachability``, which
remains the hop-receipt verdict (confirmed / likely / unlikely / unknown).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.core.severity import SEVERITY_THRESHOLD_LABELS, severity_rank
from agent_bom.graph.container import AttackPath
from agent_bom.graph.path_evidence import finding_severity_for_path

_FINDING_TYPES = frozenset({"vulnerability", "misconfiguration"})
_CREDENTIAL_TYPES = frozenset({"credential", "credential_ref"})
_AGENT_TYPES = frozenset({"agent"})

TIER_EXPLOITABLE_ENTRYPOINT = 3
TIER_FINDING = 2
TIER_EXPOSURE_ONLY = 1
TIER_NO_EVIDENCE = 0

MIN_SEVERITY_CHOICES: tuple[str, ...] = SEVERITY_THRESHOLD_LABELS


def _entity_type(node: Any) -> str:
    kind = getattr(node, "entity_type", "")
    return str(getattr(kind, "value", kind) or "")


def _hop_types(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> list[str]:
    return [_entity_type(nodes_by_id.get(hop)) for hop in path.hops]


def source_entity_type(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> str:
    node = nodes_by_id.get(path.source)
    if node is not None:
        return _entity_type(node)
    prefix, _, rest = path.source.partition(":")
    return prefix if rest else ""


def path_has_finding(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> bool:
    return bool(path.vuln_ids) or any(kind in _FINDING_TYPES for kind in _hop_types(path, nodes_by_id))


def path_has_credential(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> bool:
    return bool(path.credential_exposure) or any(kind in _CREDENTIAL_TYPES for kind in _hop_types(path, nodes_by_id))


def path_has_agent_entrypoint(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> bool:
    return source_entity_type(path, nodes_by_id) in _AGENT_TYPES


def path_is_kev(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> bool:
    for hop in path.hops:
        node = nodes_by_id.get(hop)
        if node is not None and _entity_type(node) in _FINDING_TYPES and (getattr(node, "attributes", None) or {}).get("is_kev") is True:
            return True
    return False


def path_severity(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> str:
    """Worst finding severity among the path's own hop nodes, else ``unknown``."""
    return finding_severity_for_path(path, nodes_by_id)


def path_graph_reachability(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> str:
    if not path_has_finding(path, nodes_by_id):
        return "no_finding_on_path"
    return "reachable_from_agent" if path_has_agent_entrypoint(path, nodes_by_id) else "reachable"


def path_evidence_tier(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> int:
    finding = path_has_finding(path, nodes_by_id)
    credential = path_has_credential(path, nodes_by_id)
    if finding and (credential or path_has_agent_entrypoint(path, nodes_by_id)):
        return TIER_EXPLOITABLE_ENTRYPOINT
    if finding:
        return TIER_FINDING
    if credential or path.tool_exposure:
        return TIER_EXPOSURE_ONLY
    return TIER_NO_EVIDENCE


_CONFIDENCE_RANK = {"verified": 4, "likely": 3, "structural": 2, "unassessed": 1, "disproven": 0}

_TIER_LABELS = {
    TIER_EXPLOITABLE_ENTRYPOINT: "finding reached from an agent or through a credential",
    TIER_FINDING: "finding on the path",
    TIER_EXPOSURE_ONLY: "credential or tool exposure without a finding",
    TIER_NO_EVIDENCE: "no finding, credential or tool on the path",
}

_CONFIDENCE_REASONS = {
    "verified": "Every hop has a complete, directed, provenance-backed receipt.",
    "likely": "Hop evidence supports the path with stale or producer-assessed receipts.",
    "structural": "Graph topology only; hop receipts do not establish end-to-end reachability.",
    "unassessed": "Hop evidence was never evaluated for this path.",
    "disproven": "Applicability evidence marks this path unlikely.",
}

RANKING_ORDER: tuple[str, ...] = (
    "evidence_tier",
    "is_kev",
    "severity",
    "evidence_confidence",
    "composite_risk",
    "credential_count",
)


def path_evidence_confidence(path: AttackPath) -> str:
    """How far hop receipts support the path, independent of its risk score.

    ``unassessed`` marks a path that never went through hop-evidence
    annotation, so it cannot outrank an annotated path that ties on tier,
    KEV state and severity.
    """
    reachability = str(path.reachability or "unknown").lower()
    if reachability == "unlikely":
        return "disproven"
    # Complete hops prove the route, not that the finding applies to this occurrence.
    if "insufficient_evidence" in (path.reachability_basis or []):
        return "structural"
    if reachability == "confirmed":
        return "verified"
    if reachability == "likely":
        return "likely"
    analysis = path.analysis if isinstance(path.analysis, Mapping) else {}
    return "structural" if analysis.get("status") else "unassessed"


def attack_path_rank_key(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> tuple[Any, ...]:
    """Ascending sort key: best path first, fully deterministic."""
    return (
        -path_evidence_tier(path, nodes_by_id),
        -int(path_is_kev(path, nodes_by_id)),
        -severity_rank(path_severity(path, nodes_by_id)),
        -_CONFIDENCE_RANK[path_evidence_confidence(path)],
        -float(path.composite_risk or 0.0),
        -len(path.credential_exposure),
        path.source,
        path.target,
        tuple(path.hops),
    )


def path_matches_filters(
    path: AttackPath,
    nodes_by_id: Mapping[str, Any],
    *,
    min_severity: str | None = None,
    has_credential: bool | None = None,
    source_type: str | None = None,
) -> bool:
    if min_severity and severity_rank(path_severity(path, nodes_by_id)) < severity_rank(min_severity):
        return False
    if has_credential is not None and path_has_credential(path, nodes_by_id) != has_credential:
        return False
    if source_type and source_entity_type(path, nodes_by_id) != source_type:
        return False
    return True


def rank_attack_paths(
    paths: list[AttackPath],
    nodes_by_id: Mapping[str, Any],
    *,
    min_severity: str | None = None,
    has_credential: bool | None = None,
    source_type: str | None = None,
) -> list[AttackPath]:
    kept = [
        path
        for path in paths
        if path_matches_filters(path, nodes_by_id, min_severity=min_severity, has_credential=has_credential, source_type=source_type)
    ]
    return sorted(kept, key=lambda path: attack_path_rank_key(path, nodes_by_id))


def ranking_node_ids(paths: list[AttackPath]) -> set[str]:
    """Node ids whose type/severity the ranking reads: sources, plus every hop of finding-bearing paths."""
    ids = {path.source for path in paths}
    for path in paths:
        if path.vuln_ids or path.finding_ids or len(path.hops) > 2:
            ids.update(path.hops)
    return ids


def path_ranking_factors(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> dict[str, Any]:
    """The values the queue sorts on, in sort order, with plain-language reasons."""
    tier = path_evidence_tier(path, nodes_by_id)
    kev = path_is_kev(path, nodes_by_id)
    severity = path_severity(path, nodes_by_id)
    scored = severity != "unknown"
    confidence = path_evidence_confidence(path)
    risk = float(path.composite_risk or 0.0)
    reasons = [f"Evidence tier {tier}: {_TIER_LABELS[tier]}."]
    if kev:
        reasons.append("A finding on the path is in the CISA Known Exploited Vulnerabilities catalog.")
    reasons.append(f"Worst finding severity on the path: {severity}." if scored else "No scored finding on the path (unscored).")
    reasons.append(_CONFIDENCE_REASONS[confidence])
    reasons.append(f"Composite risk {risk:g}/100 orders paths that tie on the factors above.")
    return {
        "order": list(RANKING_ORDER),
        "evidence_tier": tier,
        "is_kev": kev,
        "severity": severity,
        "severity_scored": scored,
        "evidence_confidence": confidence,
        "composite_risk": risk,
        "credential_count": len(path.credential_exposure),
        "reasons": reasons,
    }


def path_rank_fields(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> dict[str, Any]:
    reachability = path_graph_reachability(path, nodes_by_id)
    factors = path_ranking_factors(path, nodes_by_id)
    return {
        "severity": factors["severity"],
        "graph_reachable": reachability != "no_finding_on_path",
        "graph_reachability": reachability,
        "evidence_tier": factors["evidence_tier"],
        "is_kev": factors["is_kev"],
        "ranking_factors": factors,
    }


def with_rank_fields(paths: list[AttackPath], payloads: list[dict[str, Any]], nodes_by_id: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Add each path's severity / graph-reachability fields to its serialized payload."""
    for path, payload in zip(paths, payloads, strict=True):
        payload.update(path_rank_fields(path, nodes_by_id))
    return payloads


__all__ = [
    "with_rank_fields",
    "MIN_SEVERITY_CHOICES",
    "attack_path_rank_key",
    "path_evidence_tier",
    "path_graph_reachability",
    "path_matches_filters",
    "path_evidence_confidence",
    "path_rank_fields",
    "path_ranking_factors",
    "RANKING_ORDER",
    "path_severity",
    "rank_attack_paths",
    "ranking_node_ids",
]
