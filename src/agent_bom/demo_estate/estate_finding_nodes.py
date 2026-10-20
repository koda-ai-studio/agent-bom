"""Estate findings on the graph, in the product's own finding-node contract.

Every estate finding is projected onto the node :func:`finding_row_node_id`
names for it, the id a live scan's finding row lands on: one ``vuln:<CVE>`` per
advisory, one ``misconfig:<section>:<check>`` per failed benchmark check, one
IaC node per rule hit, otherwise ``misconfig:<source>:<finding-id>``. Each
finding is one *occurrence* of that node:

* the node's ``finding_ids_by_asset`` maps every holder to its findings, as
  :func:`link_findings_to_graph_nodes` records them;
* the asset holds the finding by ``vulnerable_to`` wherever the relationship
  contract admits that asset kind (the rule ``graph.finding_row_projection``
  applies), carrying that finding's id and its own applicability, so a shared
  node never lends one occurrence's verdict to another;
* ``affects`` (correlation, CNAPP overlay) and ``contains`` (roll-up parent)
  stay, except that a package's ``vulnerable_to`` already is its roll-up edge.

The per-finding ``vuln:demo-estate:<id>`` / ``misconfig:demo-estate:<id>`` ids
the estate used to mint are kept as node aliases.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.core.severity import SEVERITY_RISK_SCORE
from agent_bom.demo_estate.estate_edges import ESTATE_DATA_SOURCE, add_estate_edge
from agent_bom.evidence.finding_node_ids import finding_row_node_id
from agent_bom.graph.applicability import applicability_from_row
from agent_bom.graph.finding_row_projection import finding_signal_attributes
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.node_aliases import record_node_aliases
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.finding import Finding
    from agent_bom.graph.container import UnifiedGraph

# Finding types that are a VULNERABILITY on the graph rather than a
# MISCONFIGURATION: ``cnapp_overlay`` builds its vulnerable-resource set from
# ``VULNERABLE_TO`` edges into vulnerability nodes.
VULNERABILITY_FINDING_TYPES: frozenset[str] = frozenset({"CVE", "MALICIOUS_PACKAGE", "MALICIOUS_MODEL"})
_RETIRED_PREFIX = "demo-estate"
_ASSESSMENT = {"status": "assessed", "basis": "recorded_finding_severity_weight", "scope": "synthetic_estate_finding"}


def is_vulnerability_finding(finding: Finding) -> bool:
    return finding.finding_type.value in VULNERABILITY_FINDING_TYPES


def _advisory_id(finding: Finding) -> str:
    return str(getattr(finding, "vulnerability_id", None) or getattr(finding, "cve_id", None) or "").strip()


def retired_estate_finding_node_id(finding: Finding) -> str:
    """The per-finding id the estate minted before it followed the product contract."""
    prefix = "vuln" if is_vulnerability_finding(finding) else "misconfig"
    return f"{prefix}:{_RETIRED_PREFIX}:{finding.id}"


def _row(finding: Finding) -> dict[str, Any]:
    """The serialized-row fields ``finding_row_node_id`` reads."""
    return {
        "id": finding.id,
        "finding_type": finding.finding_type.value,
        "source": finding.source.value,
        "evidence": finding.evidence if isinstance(finding.evidence, dict) else {},
        "vulnerability_id": getattr(finding, "vulnerability_id", None),
        "cve_id": getattr(finding, "cve_id", None),
    }


def estate_finding_node_id(finding: Finding) -> str:
    """The graph node an estate finding is projected onto (the live scan's id for the same row)."""
    if is_vulnerability_finding(finding) and _advisory_id(finding):
        return f"vuln:{_advisory_id(finding)}"
    return finding_row_node_id(_row(finding)) or retired_estate_finding_node_id(finding)


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


def _finding_node(finding: Finding, node_id: str, severity: str, estate_id: str) -> UnifiedNode:
    """Attributes every occurrence of this node shares; per-occurrence facts live on the edges."""
    vulnerability = is_vulnerability_finding(finding)
    scored = severity in SEVERITY_RISK_SCORE and severity != "unknown"
    attributes: dict[str, Any] = {
        **({"risk_assessment": dict(_ASSESSMENT)} if scored else {}),
        "finding_type": finding.finding_type.value,
        "synthetic": True,
        "estate_id": estate_id,
    }
    if vulnerability:
        attributes.update({"vulnerability_id": _advisory_id(finding), **finding_signal_attributes(finding)})
    else:
        attributes.update(
            finding_source=finding.source.value,
            check_id=str(finding.evidence.get("control_id") or ""),
            cloud_provider=finding.provider or "",
        )
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.VULNERABILITY if vulnerability else EntityType.MISCONFIGURATION,
        label=_advisory_id(finding) if vulnerability else finding.title,
        severity=severity,
        risk_score=SEVERITY_RISK_SCORE.get(severity, 0.0),
        attributes=attributes,
        compliance_tags=[f"{tag.framework}:{tag.control}" for tag in finding.normalized_controls()],
        data_sources=[ESTATE_DATA_SOURCE],
        dimensions=NodeDimensions(cloud_provider="" if vulnerability else finding.provider or ""),
    )


def _record_occurrence(node: UnifiedNode, finding: Finding, asset_id: str) -> None:
    attrs = node.attributes
    mapping = attrs.get("finding_ids_by_asset")
    mapping = dict(mapping) if isinstance(mapping, dict) else {}
    mapping[asset_id] = sorted({*(mapping.get(asset_id) or []), finding.id})
    attrs["finding_ids_by_asset"] = mapping
    attrs["resource_ids"] = sorted({*(attrs.get("resource_ids") or []), asset_id})
    # The prose, not the ``Remediation`` dataclass: attributes persist as JSON.
    attrs.setdefault("recommendation", finding.remediation_guidance or "")
    attrs.setdefault("configuration", finding.evidence.get("configuration") or {})
    all_ids = {fid for ids in mapping.values() for fid in ids}
    if len(all_ids) == 1:
        attrs["finding_id"] = finding.id
        attrs["canonical_finding_id"] = finding.canonical_id
    else:
        for key in ("finding_id", "canonical_finding_id", "unified_finding_id"):
            attrs.pop(key, None)
    record_node_aliases(node, [retired_estate_finding_node_id(finding)])


def _add_occurrence_edge(graph: UnifiedGraph, source: str, target: str, relationship: RelationshipType, evidence: dict[str, Any]) -> None:
    """One edge per (holder, finding node); a second finding on it joins ``finding_ids``."""
    stored = next((e for e in graph.edges_from(source) if e.target == target and e.relationship == relationship), None)
    if stored is not None:
        stored.evidence["finding_ids"] = sorted({*(stored.evidence.get("finding_ids") or []), *evidence["finding_ids"]})
        return
    add_estate_edge(graph, source, target, relationship, evidence=evidence)


def project_estate_finding(graph: UnifiedGraph, finding: Finding, asset_id: str, *, severity: str, estate_id: str) -> str:
    """Add ``finding`` as one occurrence of its finding node; returns the node id."""
    node_id = estate_finding_node_id(finding)
    graph.add_node(_finding_node(finding, node_id, severity, estate_id))
    node = graph.nodes[node_id]
    _record_occurrence(node, finding, asset_id)
    asset_kind = graph.nodes[asset_id].entity_type
    occurrence = {
        "finding_ids": [finding.id],
        "resource_id": asset_id,
        "applicability": applicability_from_row(_occurrence_row(finding)),
        "configuration": finding.evidence.get("configuration") or {},
        **({"severity": severity} if severity else {}),
    }
    _add_occurrence_edge(graph, node_id, asset_id, RelationshipType.AFFECTS, {"finding_ids": [finding.id]})
    holds = relationship_spec(RelationshipType.VULNERABLE_TO)
    if holds is not None and holds.allows(asset_kind, node.entity_type):
        _add_occurrence_edge(graph, asset_id, node_id, RelationshipType.VULNERABLE_TO, occurrence)
    if not (asset_kind == EntityType.PACKAGE and node.entity_type == EntityType.VULNERABILITY):
        add_estate_edge(graph, asset_id, node_id, RelationshipType.CONTAINS)
    return node_id


__all__ = [
    "VULNERABILITY_FINDING_TYPES",
    "estate_finding_node_id",
    "is_vulnerability_finding",
    "project_estate_finding",
    "retired_estate_finding_node_id",
]
