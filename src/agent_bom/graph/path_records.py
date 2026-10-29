"""Serializable path, campaign and interaction evidence records."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_bom.graph.technique_mapping import TechniqueMapping


@dataclass(slots=True)
class AttackPath:
    """Precomputed attack path between two nodes."""

    source: str
    target: str
    hops: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    composite_risk: float = 0.0
    summary: str = ""
    credential_exposure: list[str] = field(default_factory=list)
    tool_exposure: list[str] = field(default_factory=list)
    vuln_ids: list[str] = field(default_factory=list)
    # Stable Finding.id values that anchor this path (preferred over CVE labels
    # in vuln_ids). Additive — empty on legacy rows; API may recompute from
    # vulnerability node attributes.finding_id.
    finding_ids: list[str] = field(default_factory=list)
    # Whether the path is executable evidence (confirmed/likely), explicitly
    # disproven (unlikely), or structural investigation context (unknown).
    reachability: str = "unknown"
    reachability_basis: list[str] = field(default_factory=list)
    # One immutable evidence receipt per directed hop. Additive and empty on
    # legacy snapshots; correlation/runtime surfaces populate this before a
    # path is presented as verified.
    hop_evidence: list[dict[str, Any]] = field(default_factory=list)
    # Snapshot-wide/path-analysis completeness. Kept separate from hop receipts
    # so bounded analysis cannot be mistaken for an exhaustive clean result.
    analysis: dict[str, Any] = field(default_factory=dict)
    # Typed MITRE ATT&CK / ATLAS techniques mapped from this path's observed
    # evidence, ordered by hop. Potential/mapped techniques for the kill-chain
    # sequence — never a claim of observed attacker activity.
    technique_mappings: list[TechniqueMapping] = field(default_factory=list)

    def mitre_technique_ids(self) -> list[str]:
        """Deduped, sorted technique IDs mapped across all hops (convenience)."""
        return sorted({m.technique_id for m in self.technique_mappings})

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "hops": self.hops,
            "edges": self.edges,
            "composite_risk": self.composite_risk,
            "summary": self.summary,
            "credential_exposure": self.credential_exposure,
            "tool_exposure": self.tool_exposure,
            "vuln_ids": self.vuln_ids,
            "finding_ids": self.finding_ids,
            "reachability": self.reachability,
            "reachability_basis": self.reachability_basis,
            "hop_evidence": self.hop_evidence,
            "analysis": self.analysis,
            "technique_mappings": [m.to_dict() for m in self.technique_mappings],
            "mitre_technique_ids": self.mitre_technique_ids(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackPath:
        return cls(
            source=data["source"],
            target=data["target"],
            hops=data.get("hops", []),
            edges=data.get("edges", []),
            composite_risk=data.get("composite_risk", 0.0),
            summary=data.get("summary", ""),
            credential_exposure=data.get("credential_exposure", []),
            tool_exposure=data.get("tool_exposure", []),
            vuln_ids=data.get("vuln_ids", []),
            finding_ids=list(data.get("finding_ids") or []),
            reachability=str(data.get("reachability") or "unknown"),
            reachability_basis=[str(item) for item in data.get("reachability_basis") or []],
            hop_evidence=[dict(item) for item in data.get("hop_evidence") or [] if isinstance(item, dict)],
            analysis=dict(data.get("analysis") or {}),
            technique_mappings=[TechniqueMapping.from_dict(m) for m in data.get("technique_mappings", [])],
        )


@dataclass(slots=True)
class Campaign:
    """A deterministic cluster of fused attack paths converging on one crown jewel.

    Campaigns are the large-estate decision surface: instead of thousands of raw
    paths, an operator sees a handful of prioritized campaigns, each grouping every
    kill-chain that terminates at the same crown-jewel data store. Identity is
    derived from ``tenant_id`` + the jewel's canonical id, so the *same estate*
    yields the *same* ``campaign_id`` across runs and backends.
    """

    campaign_id: str
    crown_jewel: str
    crown_jewel_label: str
    partition: str
    owner: str
    business_impact: str
    exploitability: float | None
    expected_risk_reduction: float | None
    path_count: int
    top_path_summary: str
    cross_partition: bool
    evidence: list[str] = field(default_factory=list)
    member_paths: list[str] = field(default_factory=list)
    priority_score: float | None = None
    priority_method: str | None = None
    exploitability_evidence: dict[str, Any] = field(default_factory=dict)
    expected_risk_reduction_evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("exploitability", "expected_risk_reduction"):
            value = getattr(self, name)
            evidence = getattr(self, f"{name}_evidence")
            refs = evidence.get("evidence_refs") if isinstance(evidence, dict) else None
            supported = (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                and value >= 0
                and isinstance(evidence, dict)
                and evidence.get("status") == "complete"
                and evidence.get("basis") in {"observed", "runtime_observed", "inferred", "modeled"}
                and isinstance(refs, list)
                and bool(refs)
                and all(isinstance(ref, str) and ref.strip() for ref in refs)
            )
            if not supported:
                setattr(self, name, None)
                setattr(
                    self, f"{name}_evidence", {"status": "unavailable", "evidence_refs": [], "reason_codes": ["assessment_not_recorded"]}
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "crown_jewel": self.crown_jewel,
            "crown_jewel_label": self.crown_jewel_label,
            "partition": self.partition,
            "owner": self.owner,
            "business_impact": self.business_impact,
            "exploitability": self.exploitability,
            "expected_risk_reduction": self.expected_risk_reduction,
            "path_count": self.path_count,
            "top_path_summary": self.top_path_summary,
            "cross_partition": self.cross_partition,
            "evidence": self.evidence,
            "member_paths": self.member_paths,
            "priority_score": self.priority_score,
            "priority_method": self.priority_method,
            "exploitability_evidence": self.exploitability_evidence,
            "expected_risk_reduction_evidence": self.expected_risk_reduction_evidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Campaign:
        return cls(
            campaign_id=str(data["campaign_id"]),
            crown_jewel=str(data.get("crown_jewel", "")),
            crown_jewel_label=str(data.get("crown_jewel_label", "")),
            partition=str(data.get("partition", "")),
            owner=str(data.get("owner", "")),
            business_impact=str(data.get("business_impact", "")),
            exploitability=data.get("exploitability"),
            expected_risk_reduction=data.get("expected_risk_reduction"),
            exploitability_evidence=data.get("exploitability_evidence", {}),
            expected_risk_reduction_evidence=data.get("expected_risk_reduction_evidence", {}),
            priority_score=data.get("priority_score"),
            priority_method=data.get("priority_method"),
            path_count=int(data.get("path_count", 0)),
            top_path_summary=str(data.get("top_path_summary", "")),
            cross_partition=bool(data.get("cross_partition", False)),
            evidence=list(data.get("evidence", [])),
            member_paths=list(data.get("member_paths", [])),
        )


@dataclass(slots=True)
class InteractionRisk:
    """Cross-agent interaction risk pattern."""

    pattern: str
    agents: list[str]
    risk_score: float
    description: str
    owasp_agentic_tag: Optional[str] = None
    # Graph node ids of ``agents``; names alone are ambiguous across scopes.
    agent_node_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "agents": self.agents,
            "agent_node_ids": self.agent_node_ids,
            "risk_score": self.risk_score,
            "description": self.description,
            "owasp_agentic_tag": self.owasp_agentic_tag,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InteractionRisk:
        return cls(
            pattern=data["pattern"],
            agents=data.get("agents", []),
            risk_score=data.get("risk_score", 0.0),
            description=data.get("description", ""),
            owasp_agentic_tag=data.get("owasp_agentic_tag"),
            agent_node_ids=[str(item) for item in data.get("agent_node_ids") or []],
        )
