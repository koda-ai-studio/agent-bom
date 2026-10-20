"""Estate vulnerability findings on the graph, in the product's own vulnerability contract.

One advisory is one ``vuln:<CVE>`` node, the id :func:`finding_row_node_id` and
the live builder mint. Each finding is one *occurrence* of it: the package
occurrence's ``VULNERABLE_TO`` edge carries that finding's id and its own
applicability (reachability plus VEX), and the node's ``finding_ids_by_asset``
maps every holder to its findings, as :mod:`agent_bom.graph.blast_projection`
and :func:`link_findings_to_graph_nodes` record them for a live scan. A shared
advisory therefore never lends one occurrence's verdict to another.

The per-occurrence ``vuln:demo-estate:<finding-id>`` ids the estate used to mint
are kept as node aliases, so saved links and stored snapshots still resolve.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.core.severity import SEVERITY_RISK_SCORE
from agent_bom.demo_estate.estate_edges import ESTATE_DATA_SOURCE, add_estate_edge
from agent_bom.graph.applicability import applicability_from_row
from agent_bom.graph.finding_row_projection import finding_signal_attributes
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.node_aliases import record_node_aliases
from agent_bom.graph.types import EntityType, RelationshipType

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.finding import Finding
    from agent_bom.graph.container import UnifiedGraph

# Finding types that are a VULNERABILITY on the graph rather than a
# MISCONFIGURATION: ``cnapp_overlay`` builds its vulnerable-resource set from
# ``VULNERABLE_TO`` edges, so a CVE projected as a misconfiguration could never
# take part in an internet-exposed-and-vulnerable combination.
VULNERABILITY_FINDING_TYPES: frozenset[str] = frozenset({"CVE", "MALICIOUS_PACKAGE", "MALICIOUS_MODEL"})
_RETIRED_PREFIX = "demo-estate"


def is_vulnerability_finding(finding: Finding) -> bool:
    return finding.finding_type.value in VULNERABILITY_FINDING_TYPES


def _advisory_id(finding: Finding) -> str:
    return str(getattr(finding, "vulnerability_id", None) or getattr(finding, "cve_id", None) or "").strip()


def retired_estate_finding_node_id(finding: Finding) -> str:
    """The per-occurrence id the estate minted before it followed the product contract."""
    prefix = "vuln" if is_vulnerability_finding(finding) else "misconfig"
    return f"{prefix}:{_RETIRED_PREFIX}:{finding.id}"


def estate_finding_node_id(finding: Finding) -> str:
    """The graph node an estate finding is projected onto.

    A vulnerability with an advisory id is that advisory's ``vuln:<id>`` node;
    anything else keeps its per-finding node.
    """
    advisory = _advisory_id(finding)
    if is_vulnerability_finding(finding) and advisory:
        return f"vuln:{advisory}"
    return retired_estate_finding_node_id(finding)


def _occurrence_row(finding: Finding) -> dict[str, Any]:
    """The finding's own reachability and VEX fields, the row ``applicability_from_row`` reads."""
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    row: dict[str, Any] = {
        "reachability": getattr(finding, "reachability", None),
        "graph_reachable": getattr(finding, "graph_reachable", None),
    }
    for key in ("symbol_reachability", "dependency_reachable", "vex_status", "vex_justification", "vex_source"):
        value = evidence.get(key)
        if value is not None:
            row[key] = value
    return row


def _advisory_node(finding: Finding, node_id: str, severity: str, estate_id: str) -> UnifiedNode:
    """Advisory-level attributes only: nothing here differs between occurrences."""
    advisory = _advisory_id(finding)
    scored = severity in SEVERITY_RISK_SCORE and severity != "unknown"
    assessment = {"status": "assessed", "basis": "recorded_finding_severity_weight", "scope": "synthetic_estate_finding"}
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.VULNERABILITY,
        label=advisory,
        severity=severity,
        risk_score=SEVERITY_RISK_SCORE.get(severity, 0.0),
        attributes={
            **({"risk_assessment": assessment} if scored else {}),
            "vulnerability_id": advisory,
            "finding_type": finding.finding_type.value,
            **finding_signal_attributes(finding),
            "synthetic": True,
            "estate_id": estate_id,
        },
        compliance_tags=[f"{tag.framework}:{tag.control}" for tag in finding.normalized_controls()],
        data_sources=[ESTATE_DATA_SOURCE],
    )


def _record_occurrence(node: UnifiedNode, finding: Finding, asset_id: str) -> None:
    attrs = node.attributes
    mapping = attrs.get("finding_ids_by_asset")
    mapping = dict(mapping) if isinstance(mapping, dict) else {}
    mapping[asset_id] = sorted({*(mapping.get(asset_id) or []), finding.id})
    attrs["finding_ids_by_asset"] = mapping
    attrs["resource_ids"] = sorted({*(attrs.get("resource_ids") or []), asset_id})
    attrs.setdefault("recommendation", finding.remediation_guidance or "")
    all_ids = {fid for ids in mapping.values() for fid in ids}
    if len(all_ids) == 1:
        attrs["finding_id"] = finding.id
        attrs["canonical_finding_id"] = finding.canonical_id
    else:
        for key in ("finding_id", "canonical_finding_id", "unified_finding_id"):
            attrs.pop(key, None)
    record_node_aliases(node, [retired_estate_finding_node_id(finding)])


def project_estate_vulnerability(graph: UnifiedGraph, finding: Finding, asset_id: str, *, severity: str, estate_id: str) -> str:
    """Add ``finding`` as one occurrence of its advisory node; returns the node id."""
    node_id = estate_finding_node_id(finding)
    graph.add_node(_advisory_node(finding, node_id, severity, estate_id))
    _record_occurrence(graph.nodes[node_id], finding, asset_id)
    occurrence = {
        "finding_ids": [finding.id],
        "resource_id": asset_id,
        "applicability": applicability_from_row(_occurrence_row(finding)),
        "configuration": finding.evidence.get("configuration") or {},
        **({"severity": severity} if severity else {}),
    }
    add_estate_edge(graph, node_id, asset_id, RelationshipType.AFFECTS, evidence={"finding_ids": [finding.id]})
    if graph.nodes[asset_id].entity_type != EntityType.PACKAGE:
        add_estate_edge(graph, asset_id, node_id, RelationshipType.CONTAINS)
    add_estate_edge(graph, asset_id, node_id, RelationshipType.VULNERABLE_TO, evidence=occurrence)
    return node_id


__all__ = [
    "VULNERABILITY_FINDING_TYPES",
    "estate_finding_node_id",
    "is_vulnerability_finding",
    "project_estate_vulnerability",
    "retired_estate_finding_node_id",
]
