"""Truthful, per-hop evidence receipts for materialized attack paths."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from agent_bom.evidence.semantics import ExploitabilityDimension
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.correlation_scope import CORRELATION_IDENTITY_VERSION
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import recorded_tier
from agent_bom.graph.hop_evidence import authority_evidence, runtime_evidence_references
from agent_bom.graph.runtime_receipts import runtime_receipts_limited, runtime_records
from agent_bom.graph.types import RelationshipType

HopEdges = dict[tuple[str, str], list[UnifiedEdge]]

STRUCTURAL_EXPOSURE_SUMMARY = (
    "Graph topology links an agent/server to a vulnerable component. Listed tools and "
    "credential references are context; effective permission, successful use, and exploitation "
    "require separate evidence."
)
_LEGACY_STRUCTURAL_SUMMARY = (
    "Evidence-backed graph path: vulnerable package/server is reachable from an agent and inherits the server's credential/tool exposure."
)


def _qualify_structural_summary(summary: str) -> str:
    # These are known generated explanations, not arbitrary source receipts.
    # Qualify them on read without rewriting the stored snapshot or custom text.
    if summary in {_LEGACY_STRUCTURAL_SUMMARY, f"Unverified structural candidate. {_LEGACY_STRUCTURAL_SUMMARY}"}:
        return STRUCTURAL_EXPOSURE_SUMMARY
    return summary


_RUNTIME_RELATIONSHIPS = frozenset(
    {
        RelationshipType.INVOKED.value,
        RelationshipType.ACCESSED.value,
    }
)


def _relationship(edge: UnifiedEdge) -> str:
    return edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)


def _correlation_provenance(edge: UnifiedEdge) -> dict[str, Any]:
    value = edge.provenance.get("correlation") if isinstance(edge.provenance, dict) else None
    return dict(value) if isinstance(value, dict) else {}


def _source_snapshot_ids(edge: UnifiedEdge, graph: UnifiedGraph) -> list[str]:
    correlation = _correlation_provenance(edge)
    raw = correlation.get("source_scan_ids")
    values = [str(item).strip() for item in raw] if isinstance(raw, list) else []
    if not values:
        fallback = str(edge.source_scan_id or graph.scan_id).strip()
        values = [fallback] if fallback else []
    return sorted(set(item for item in values if item))


def _correlation_identity_current(edge: UnifiedEdge) -> bool:
    correlation = _correlation_provenance(edge)
    return not correlation or correlation.get("identity_version") == CORRELATION_IDENTITY_VERSION


def _has_relationship_provenance(edge: UnifiedEdge) -> bool:
    """Require an edge-level receipt; snapshot membership alone is structural."""

    correlation = _correlation_provenance(edge)
    observations = correlation.get("observations")
    if isinstance(observations, list) and any(
        isinstance(item, Mapping)
        and str(item.get("scan_id") or "").strip()
        and str(item.get("source_edge_id") or "").strip()
        and str(item.get("evidence_digest") or "").strip()
        for item in observations
    ):
        return True

    provenance_source = edge.provenance.get("source") if isinstance(edge.provenance, dict) else None
    relationship_evidence = {key: value for key, value in edge.evidence.items() if key != "freshness"}
    return bool(str(provenance_source or "").strip() or relationship_evidence)


def _freshness(edge: UnifiedEdge) -> str:
    correlation = _correlation_provenance(edge)
    value = correlation.get("freshness") or edge.evidence.get("freshness")
    return str(value or "unknown")


def _runtime_state(edge: UnifiedEdge) -> str:
    # A denial is an observed attempt, never evidence of a completed action.
    # Negative facts win even if another source supplied an "observed" label.
    if (
        edge.evidence.get("blocked") is True
        or edge.evidence.get("decision") in ("blocked", "denied", "explicit_deny", "implicit_deny")
        or edge.evidence.get("runtime_observed_state") == "blocked"
        or edge.provenance.get("runtime_observed_state") == "blocked"
    ):
        return "blocked"
    if any(
        record.get("blocked") is True
        or record.get("decision") in ("blocked", "denied", "explicit_deny", "implicit_deny")
        or record.get("runtime_observed_state") == "blocked"
        for record in runtime_records(edge.evidence)
    ):
        return "blocked"
    explicit = edge.evidence.get("runtime_observed_state") or edge.provenance.get("runtime_observed_state")
    if explicit in ("observed", "blocked", "not_observed"):
        return str(explicit)
    if _relationship(edge) in _RUNTIME_RELATIONSHIPS or edge.evidence.get("runtime_observed"):
        return "observed"
    return "not_observed"


def _runtime_outcome(edge: UnifiedEdge) -> str:
    """Retain failed aggregate attempts without inferring downstream success."""
    if _runtime_state(edge) == "blocked":
        return "blocked"
    for record in runtime_records(edge.evidence):
        observed = record.get("observation_count", record.get("count"))
        failed = record.get("failure_count", record.get("error_count"))
        if type(observed) is int and type(failed) is int and observed > 0 and failed == observed:
            return "failed"
    # A permitted invocation or an event without an error is not an outcome
    # receipt. Mixed aggregates also cannot identify which action succeeded.
    return "unknown"


def _runtime_reasons(receipts: Sequence[Mapping[str, Any]]) -> list[str]:
    reasons: list[str] = []
    if any(item.get("runtime_observed_state") == "blocked" or item.get("runtime_outcome") == "blocked" for item in receipts):
        reasons.append("blocked_runtime_hop")
    if any(item.get("runtime_outcome") == "failed" for item in receipts):
        reasons.append("failed_runtime_outcome")
    return reasons


def _evidence_tier(edge: UnifiedEdge) -> str:
    return recorded_tier(edge.evidence)


def _analysis(graph: UnifiedGraph, *, hop_count: int, path: AttackPath | None = None) -> dict[str, Any]:
    target = graph.nodes.get(path.target) if path is not None else None
    credential_assessment = target is not None and target.attributes.get("rule_id") == "AGENT_REACHES_PRIVILEGED"
    analyzer = "credential_finding_paths" if credential_assessment else "attack_path_fusion"
    status = graph.analysis_status.get(analyzer)
    if status is None:
        return {
            "status": "not_recorded",
            "reason_codes": ["analysis_not_recorded"],
            "limits": {},
            "observed": {"hop_count": hop_count},
        }
    result = status.to_dict()
    observed = dict(result.get("observed") or {})
    observed["hop_count"] = hop_count
    result["observed"] = observed
    return result


def resolve_typed_hop(
    graph: UnifiedGraph, source: str, target: str, relationship: str, hop_edges: HopEdges | None = None
) -> tuple[UnifiedEdge | None, str | None]:
    """Resolve one exact directed key; never choose a representative witness."""
    if not relationship:
        return None, "hop_relationship_missing"
    try:
        RelationshipType(relationship)
    except ValueError:
        return None, "unsupported_hop_relationship"
    candidates = [
        edge
        for edge in (hop_edges.get((source, target), []) if hop_edges is not None else graph.adjacency.get(source, []))
        if edge.source == source and edge.target == target and _relationship(edge) == relationship
    ]
    if len(candidates) != 1:
        return None, "ambiguous_hop_relationship" if candidates else "hop_relationship_not_recorded"
    return candidates[0], None


def annotate_attack_path_evidence(path: AttackPath, graph: UnifiedGraph, *, hop_edges: HopEdges | None = None) -> AttackPath:
    """Attach deterministic hop receipts and conservatively classify truth."""

    path.summary = _qualify_structural_summary(path.summary)
    receipts: list[dict[str, Any]] = []
    for index, (source, target) in enumerate(zip(path.hops, path.hops[1:])):
        relationship = path.edges[index] if index < len(path.edges) else ""
        edge, gap = resolve_typed_hop(graph, source, target, relationship, hop_edges)
        if edge is None:
            receipts.append(
                {
                    "source_node_id": source,
                    "target_node_id": target,
                    "relationship": relationship,
                    "reason_codes": [gap],
                    "source_snapshot_ids": [],
                    "relationship_provenance": "unavailable",
                    "correlation_identity_status": "unavailable",
                    "evidence_tier": "unknown",
                    "confidence": 0.0,
                    "freshness": "unknown",
                    "runtime_observed_state": "not_observed",
                    "direction": "unknown",
                    "traversable": False,
                    "complete": False,
                    "truncated": False,
                }
            )
            continue
        source_ids = _source_snapshot_ids(edge, graph)
        freshness = _freshness(edge)
        authority = authority_evidence(edge.evidence)
        receipts.append(
            {
                "source_node_id": source,
                "target_node_id": target,
                "relationship": _relationship(edge),
                "canonical_edge_id": edge.canonical_id,
                "reason_codes": ["runtime_receipts_limited"] if runtime_receipts_limited(edge.evidence) else [],
                "source_snapshot_ids": source_ids,
                "relationship_provenance": "recorded" if _has_relationship_provenance(edge) else "unavailable",
                "correlation_identity_status": "current" if _correlation_identity_current(edge) else "recomputation_required",
                "evidence_tier": _evidence_tier(edge),
                "confidence": float(edge.confidence),
                "freshness": freshness,
                "runtime_observed_state": _runtime_state(edge),
                "runtime_references": runtime_evidence_references(edge.evidence) if _runtime_state(edge) in {"observed", "blocked"} else [],
                **({"runtime_outcome": _runtime_outcome(edge)} if _runtime_outcome(edge) != "unknown" else {}),
                "direction": edge.direction,
                "traversable": bool(edge.traversable),
                "complete": bool(
                    edge.traversable
                    and not runtime_receipts_limited(edge.evidence)
                    and edge.direction == "directed"
                    and source_ids
                    and _has_relationship_provenance(edge)
                    and _correlation_identity_current(edge)
                    and freshness in {"fresh", "stale_allowed"}
                    and edge.source == source
                    and edge.target == target
                ),
                "truncated": False,
                **({"authority": authority} if authority is not None else {}),
            }
        )

    analysis = _analysis(graph, hop_count=max(len(path.hops) - 1, 0), path=path)
    truncated = analysis.get("status") in {"limited", "skipped", "failed", "not_recorded"}
    if truncated:
        for receipt in receipts:
            receipt["truncated"] = True
    if any(receipt.get("correlation_identity_status") == "recomputation_required" for receipt in receipts):
        if "correlation_recomputation_required" not in path.reachability_basis:
            path.reachability_basis.append("correlation_recomputation_required")
    path.hop_evidence = receipts
    path.analysis = analysis

    # A path must contain at least one relationship. Without this guard a
    # single-node structural finding satisfies ``all([])`` and is promoted to
    # confirmed despite having no directed, provenance-backed hop.
    all_complete = (
        bool(receipts)
        and len(receipts) == max(len(path.hops) - 1, 0)
        and all(receipt["complete"] and not receipt["truncated"] for receipt in receipts)
    )
    stale = any(str(receipt["freshness"]).startswith("stale") for receipt in receipts)
    runtime_reasons = _runtime_reasons(receipts)
    if runtime_reasons:
        path.reachability = "unknown"
        path.composite_risk = min(path.composite_risk, 39.0)
        path.reachability_basis = list(dict.fromkeys([*path.reachability_basis, *runtime_reasons]))
    elif not all_complete and path.reachability != "unlikely":
        path.reachability = "unknown"
        path.composite_risk = min(path.composite_risk, 39.0)
        if "incomplete_hop_evidence" not in path.reachability_basis:
            path.reachability_basis.append("incomplete_hop_evidence")
    elif stale:
        if path.reachability == "confirmed":
            path.reachability = "likely"
        if "stale_evidence_allowed" not in path.reachability_basis:
            path.reachability_basis.append("stale_evidence_allowed")
    elif all_complete and path.reachability in {"unknown", "likely"}:
        path.reachability = "confirmed"
        if "directed_provenance_backed_hops" not in path.reachability_basis:
            path.reachability_basis.append("directed_provenance_backed_hops")
    return path


def _unavailable_dimension(reason: str, **facts: object) -> dict[str, Any]:
    return {
        "status": "unavailable",
        **facts,
        "basis": [],
        "reasonCodes": [reason],
    }


def _path_completeness(path: AttackPath) -> dict[str, Any]:
    """Project only recorded analyzer and hop coverage; never infer complete."""

    analysis = path.analysis if isinstance(path.analysis, Mapping) else {}
    analysis_status = str(analysis.get("status") or "")
    analysis_reasons = [str(item) for item in analysis.get("reason_codes", []) if str(item)]
    receipts = [item for item in path.hop_evidence if isinstance(item, Mapping)]
    expected_hops = max(len(path.hops) - 1, 0)
    base = {
        "expectedHops": expected_hops,
        "evidencedHops": len(receipts),
        "analysisStatus": analysis_status or None,
    }
    if not analysis_status:
        return {"status": "unavailable", **base, "reasonCodes": ["analysis_not_recorded"]}
    if analysis_status == "failed":
        return {"status": "failed", **base, "reasonCodes": analysis_reasons or ["analysis_failed"]}
    if analysis_status in {"skipped", "not_recorded"}:
        return {"status": "unavailable", **base, "reasonCodes": analysis_reasons or [analysis_status]}
    if analysis_status == "limited":
        return {"status": "partial", **base, "reasonCodes": analysis_reasons or ["analysis_limited"]}
    if analysis_status != "complete":
        return {"status": "unavailable", **base, "reasonCodes": ["analysis_status_unknown"]}
    runtime_reasons = _runtime_reasons(receipts)
    if runtime_reasons:
        return {"status": "partial", **base, "reasonCodes": runtime_reasons}
    if expected_hops and not receipts:
        return {"status": "unavailable", **base, "reasonCodes": ["hop_evidence_not_recorded"]}
    if len(receipts) != expected_hops or any(item.get("truncated") for item in receipts):
        return {"status": "partial", **base, "reasonCodes": ["incomplete_hop_evidence"]}
    if any(str(item.get("freshness") or "unknown") not in {"fresh", "stale_allowed"} for item in receipts):
        return {"status": "partial", **base, "reasonCodes": ["unknown_evidence_freshness"]}
    ordered = (
        expected_hops > 0
        and len(path.edges) == expected_hops
        and path.source == path.hops[0]
        and path.target == path.hops[-1]
        and all(
            item.get("source_node_id") == path.hops[index]
            and item.get("target_node_id") == path.hops[index + 1]
            and item.get("relationship") == path.edges[index]
            and bool(path.edges[index])
            and item.get("complete") is True
            and item.get("truncated") is False
            and item.get("direction") == "directed"
            and item.get("traversable") is True
            and item.get("relationship_provenance") == "recorded"
            and item.get("correlation_identity_status") == "current"
            and isinstance(item.get("source_snapshot_ids"), list)
            and bool(item["source_snapshot_ids"])
            and all(isinstance(ref, str) and ref.strip() for ref in item["source_snapshot_ids"])
            for index, item in enumerate(receipts)
        )
    )
    if not ordered:
        return {"status": "partial", **base, "reasonCodes": ["incomplete_hop_evidence"]}
    if any(item.get("freshness") != "fresh" for item in receipts):
        return {"status": "partial", **base, "reasonCodes": ["stale_evidence_allowed"]}
    return {"status": "complete", **base, "reasonCodes": []}


def exposure_advisory_evidence(target_node: Any | None) -> dict[str, Any] | None:
    """Shared advisory signals; these are not environment exploitability verdicts."""
    if target_node is None:
        return None
    attributes = getattr(target_node, "attributes", {}) or {}
    return {
        "cvssScore": attributes.get("cvss_score"),
        "cvssVector": attributes.get("cvss_vector"),
        "epssScore": attributes.get("epss_score"),
        "isKev": attributes.get("is_kev"),
        "attackVector": attributes.get("attack_vector"),
        "attackComplexity": attributes.get("attack_complexity"),
        "privilegesRequired": attributes.get("privileges_required"),
        "userInteraction": attributes.get("user_interaction"),
        "networkExploitable": attributes.get("network_exploitable"),
        "impactCategory": attributes.get("impact_category"),
        "source": "graph_attack_path",
    }


def exposure_evidence_dimensions(
    path: AttackPath, target_node: Any | None, *, relationships: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Build independent evidence dimensions shared by graph response surfaces."""

    attributes = getattr(target_node, "attributes", {}) if target_node is not None else {}
    attributes = attributes if isinstance(attributes, Mapping) else {}
    completeness = _path_completeness(path)
    if relationships is not None and completeness["status"] == "complete":
        directed_edges = {
            (item.get("source"), item.get("target"), item.get("relationship"))
            for item in relationships
            if item.get("direction") == "directed" and item.get("traversable") is True
        }
        if any((source, path.hops[index + 1], path.edges[index]) not in directed_edges for index, source in enumerate(path.hops[:-1])):
            completeness = {**completeness, "status": "partial", "reasonCodes": ["matching_topology_not_recorded"]}

    reachability_value = str(path.reachability or "").lower()
    reachability_basis = [str(item) for item in path.reachability_basis if str(item)]
    runtime_reasons = _runtime_reasons([item for item in path.hop_evidence if isinstance(item, Mapping)])
    reachability_supported = not runtime_reasons and (
        completeness["status"] == "complete" or (completeness["status"] == "partial" and reachability_value in {"likely", "unlikely"})
    )
    if reachability_value in {"confirmed", "likely", "unlikely"} and reachability_basis and reachability_supported:
        reachability = {
            "status": completeness["status"],
            "verdict": reachability_value,
            "basis": reachability_basis,
        }
        if completeness["status"] == "partial":
            reachability["reasonCodes"] = list(completeness["reasonCodes"])
    else:
        reachability = _unavailable_dimension("reachability_not_assessed", verdict=None)

    # CVSS AV:N, KEV, EPSS and naked imported labels describe signals, not an
    # environment-specific assessment. Reuse the evidence contract, including
    # its reference and partial/unavailable validation.
    assessment = None
    try:
        assessment = ExploitabilityDimension.model_validate(attributes.get("exploitability_assessment"))
    except ValidationError:
        pass
    if assessment is not None:
        exploitability = {
            "status": assessment.status.value,
            "verdict": assessment.verdict.value if assessment.verdict is not None else None,
            "basis": ["finding_assessment:exploitability"],
            "evidenceRefs": list(assessment.evidence_refs),
            "reasonCodes": list(assessment.reason_codes),
        }
    else:
        exploitability = _unavailable_dimension("exploitability_not_assessed", verdict=None)

    impact_category = str(attributes.get("impact_category") or "").strip()
    impact = (
        {
            "status": "complete",
            "category": impact_category,
            "basis": ["finding_attribute:impact_category"],
        }
        if impact_category
        else _unavailable_dimension("impact_not_assessed", category=None)
    )

    explicit_actionability = attributes.get("actionability")
    if isinstance(explicit_actionability, bool):
        actionability = {
            "status": "complete",
            "actionable": explicit_actionability,
            "basis": ["finding_attribute:actionability"],
        }
    elif attributes.get("actionable") is True:
        actionability = {
            "status": "complete",
            "actionable": True,
            "basis": ["finding_attribute:actionable"],
        }
    elif attributes.get("fixed_version") or attributes.get("remediation"):
        actionability = {
            "status": "complete",
            "actionable": True,
            "basis": ["finding_remediation_evidence"],
        }
    else:
        actionability = _unavailable_dimension("actionability_not_assessed", actionable=None)

    return {
        "reachability": reachability,
        "exploitability": exploitability,
        "impact": impact,
        "actionability": actionability,
        "completeness": completeness,
    }


def finding_severity_for_path(path: AttackPath, nodes_by_id: Mapping[str, Any]) -> str:
    """Keep finding severity independent of permission-bearing asset priority."""
    from agent_bom.core.severity import severity_rank

    known = []
    for hop in path.hops:
        node = nodes_by_id.get(hop)
        kind = getattr(node, "entity_type", "")
        kind = getattr(kind, "value", kind)
        severity = str(getattr(node, "severity", "") or "").lower()
        if kind in {"vulnerability", "misconfiguration"} and severity in {"critical", "high", "medium", "low", "none"}:
            known.append(severity)
    return max(known, key=severity_rank, default="unknown")


def qualify_exposure_reachability(payload: dict[str, Any]) -> dict[str, Any]:
    """Qualify legacy projection labels without rewriting historical receipts."""
    previous_summary = payload.get("summary")
    if isinstance(previous_summary, str):
        payload["summary"] = _qualify_structural_summary(previous_summary)
        if payload.get("label") == previous_summary:
            payload["label"] = payload["summary"]
    dimensions = payload["evidenceDimensions"]
    if payload.get("reachability") == "confirmed" and dimensions["reachability"].get("verdict") != "confirmed":
        payload["reachability"] = "unknown"
        reasons = dimensions["completeness"].get("reasonCodes") or ["incomplete_hop_evidence"]
        payload["reachabilityBasis"] = list(dict.fromkeys([*payload.get("reachabilityBasis", []), *reasons]))
        previous_summary = payload.get("summary")
        payload["summary"] = "Structural exposure candidate; available hop evidence does not establish end-to-end reachability."
        if payload.get("label") == previous_summary:
            payload["label"] = payload["summary"]
    return payload


__all__ = [
    "annotate_attack_path_evidence",
    "exposure_evidence_dimensions",
    "package_path_covers_rollup",
    "rank_attack_path",
]


def with_technique_mappings(paths: list[AttackPath], graph: UnifiedGraph) -> list[AttackPath]:
    """Annotate a batch without rescanning a shared credential's finding fan-out.

    The hop index covers only the sources the batch's paths traverse, so the
    cost tracks the paths, not the whole graph, and an empty batch is free.
    """
    if not paths:
        return paths
    hop_edges: HopEdges = {}
    for source in {hop for path in paths for hop in path.hops[:-1]}:
        for edge in graph.adjacency.get(source, []):
            hop_edges.setdefault((source, edge.target), []).append(edge)
    for path in paths:
        annotate_attack_path_evidence(path, graph, hop_edges=hop_edges)
    try:
        from agent_bom.graph.attack_path_mitre import TechniqueCatalogs, derive_attack_path_techniques

        catalogs = TechniqueCatalogs()
        for path in paths:
            path.technique_mappings = derive_attack_path_techniques(path, graph, catalogs)
    except Exception:  # noqa: BLE001
        pass
    return paths


def package_path_covers_rollup(finding_edge: Any, incoming: dict[str, list]) -> bool:
    """A server->finding edge rolled up from packages repeats an exposure whose
    server->package->finding path is already derived; count it once."""
    derived_via = (getattr(finding_edge, "evidence", None) or {}).get("derived_via")
    if not isinstance(derived_via, list):
        return False
    server, finding = finding_edge.source, finding_edge.target
    finding_sources = {e.source for e in incoming.get(finding, []) if _relationship(e) == RelationshipType.VULNERABLE_TO.value}
    return any(
        pkg in finding_sources
        and any(e.source == server and _relationship(e) == RelationshipType.DEPENDS_ON.value for e in incoming.get(pkg, []))
        for pkg in derived_via
        if isinstance(pkg, str)
    )


def rank_attack_path(path: AttackPath) -> tuple:
    """Highest risk first; equal-risk paths fall back to a stable identity order
    so tied credential-reach paths never depend on graph insertion order."""
    return (
        -path.composite_risk,
        -len(path.hops),
        -len(path.credential_exposure),
        -len(path.tool_exposure),
        path.source,
        path.target,
        tuple(path.hops),
        tuple(path.edges),
    )


def tag_path_kinds(kinds: dict[int, str] | None, **families: list[AttackPath]) -> None:
    if kinds is None:
        return
    for family, members in families.items():
        kinds.update({id(path): family for path in members})


def rank_unique_paths(paths: list[AttackPath]) -> list[AttackPath]:
    """One served path per hop/edge chain (highest-ranked wins); never empty or a loop.

    A single-hop entry is a standing principal finding (admin-equivalent role,
    toxic combination) that must still reach the queue, so it is kept.
    """
    unique: list[AttackPath] = []
    served: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    for path in sorted(paths, key=rank_attack_path):
        identity = (path.source, path.target, tuple(path.hops), tuple(path.edges))
        if identity in served or not path.hops or (len(path.hops) > 1 and path.source == path.target):
            continue
        served.add(identity)
        unique.append(path)
    return unique
