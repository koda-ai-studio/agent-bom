"""Serializable compliance narrative contracts and claim boundary."""

from __future__ import annotations

from dataclasses import dataclass, field

COMPLIANCE_CLAIM_BOUNDARY = (
    "Vulnerability-to-control mappings are review evidence, not a determination of compliance, "
    "certification, audit result, or regulatory breach."
)


@dataclass
class ControlNarrative:
    """Auditor-facing explanation of a single failing control."""

    control_id: str
    title: str
    status: str  # "pass" | "warning" | "fail"
    narrative: str
    affected_packages: list[str] = field(default_factory=list)
    affected_agents: list[str] = field(default_factory=list)
    # The vulnerability ids that mapped onto this control. Without them an
    # auditor can only walk control -> package and can never tie the control
    # assertion back to the finding that produced it.
    affected_findings: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)


@dataclass
class FrameworkNarrative:
    """Per-framework compliance story."""

    framework: str  # display name, e.g. "OWASP Top 10 for LLM"
    slug: str  # e.g. "owasp-llm"
    status: str  # "evidence_current" | "review" | "action_required" | "not_evaluated"
    score: int  # 0-100, over evaluated controls only (0 when nothing evaluated)
    narrative: str  # 2-3 sentences
    failing_controls: list[ControlNarrative] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class RemediationImpact:
    """How a single package upgrade maps to compliance controls."""

    package: str
    current_version: str
    fix_version: str  # empty string when no fix is available
    controls_fixed: list[str]  # control codes, e.g. ["LLM03", "MCP04"]
    frameworks_impacted: list[str]  # framework display names
    narrative: str  # "Upgrading X from Y to Z fixes controls A, B, C"


@dataclass
class ComplianceNarrative:
    """Full review-ready compliance story from a scan."""

    executive_summary: str
    framework_narratives: list[FrameworkNarrative]
    remediation_impact: list[RemediationImpact]
    risk_narrative: str
    generated_at: str  # ISO 8601
    claim_boundary: str = COMPLIANCE_CLAIM_BOUNDARY
    # Catalog-backed NIST SP 800-53 Rev 5 line (vendor-asserted), scored over
    # EVALUATED controls only, with ISO-by-id attribution — the same
    # representation the /v1/compliance API line reports (one source of truth).
    # Empty dict when a single-framework narrative is scoped to a non-NIST slug.
    nist_800_53_catalog: dict = field(default_factory=dict)
    # One-paragraph leadership read plus the top risks it names, from the same
    # rows the framework sections evaluate (see agent_bom.output.executive_headline).
    executive_headline: dict = field(default_factory=dict)
