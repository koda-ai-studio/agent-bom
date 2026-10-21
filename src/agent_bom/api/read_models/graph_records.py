"""Stable graph wire records shared by the documented read endpoints.

These describe serialized records, including derived identities and provenance;
provider-specific attributes and evidence remain open objects. Routes retain
plain-dict serialization through ``documented``; contract tests validate records.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from agent_bom.api.read_models._base import ReadModel
from agent_bom.graph.technique_mapping import TechniqueMapping


class GraphNodeDimensions(ReadModel):
    ecosystem: str = Field(default_factory=str)
    cloud_provider: str = Field(default_factory=str)
    agent_type: str = Field(default_factory=str)
    surface: str = Field(default_factory=str)
    environment: str = Field(default_factory=str)


class GraphNodeRiskAssessment(ReadModel):
    status: Literal["assessed", "not_assessed"]
    basis: str | None
    scope: str | None


class GraphNodeProvenance(ReadModel):
    schema_version: str
    tier: str
    sources: list[str]
    source_snapshot_ids: list[str]
    first_seen: str | None
    last_seen: str | None
    time_basis: str
    execution: str


class GraphAgentRecord(ReadModel):
    id: str
    label: str
    risk_score: float
    risk_assessment: GraphNodeRiskAssessment
    severity: str
    status: str
    data_sources: list[str]
    first_seen: str
    last_seen: str


class GraphCanvasNodeRecord(GraphAgentRecord):
    """Fields retained by the compact canvas projection."""

    entity_type: str
    attributes: dict[str, Any]
    compliance_tags: list[str]
    dimensions: GraphNodeDimensions


class GraphNodeRecord(GraphCanvasNodeRecord):
    """The full public ``UnifiedNode.to_dict`` shape."""

    canonical_id: str
    evidence_provenance: GraphNodeProvenance
    category_uid: int
    class_uid: int
    type_uid: int
    severity_id: int


class GraphCanvasEdgeRecord(ReadModel):
    """Fields retained by the compact canvas projection."""

    id: str
    source: str
    target: str
    relationship: str
    direction: str
    weight: float
    traversable: bool
    first_seen: str
    last_seen: str
    confidence: float
    provenance: dict[str, Any]
    source_scan_id: str
    evidence: dict[str, Any]


class GraphEdgeRecord(GraphCanvasEdgeRecord):
    """The full public ``UnifiedEdge.to_dict`` shape, including validity."""

    canonical_id: str
    source_id: str
    target_id: str
    valid_from: str
    valid_to: str | None
    source_run_id: str
    activity_id: int


class GraphAttackPathSummary(ReadModel):
    """The bounded roll-up projection intentionally omits detailed hop evidence."""

    source: str
    target: str
    hops: list[str]
    composite_risk: float
    summary: str


class GraphAttackPathRecord(GraphAttackPathSummary):
    """Serialized attack path; recorded reachability never implies execution."""

    edges: list[str]
    credential_exposure: list[str]
    tool_exposure: list[str]
    vuln_ids: list[str]
    finding_ids: list[str]
    reachability: str
    reachability_basis: list[str]
    hop_evidence: list[dict[str, Any]]
    analysis: dict[str, Any]
    technique_mappings: list[TechniqueMapping]
    mitre_technique_ids: list[str]
    # Queue/presentation enrichments are absent on the underlying stored path.
    severity: str | None = None
    ranking_factors: dict[str, Any] | None = None
    exposure_path: dict[str, Any] | None = None
