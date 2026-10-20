"""Compliance models for the public API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ComplianceEvidenceItem(BaseModel):
    finding_id: str
    control_tag: str
    vulnerability_id: str | None = None
    package: str | None = None
    severity: str | None = None
    scan_id: str | None = None
    scan_input: dict[str, Any] = Field(default_factory=dict)
    scanner_version: str | None = None
    scan_started_at: str | None = None
    scan_completed_at: str | None = None
    policy_decisions: list[dict[str, Any]] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    fixed_version: str | None = None
    agents_at_risk: list[str] = Field(default_factory=list)


class ComplianceReportControl(BaseModel):
    control_id: str | None = None
    control_name: str | None = None
    status: str = "unknown"
    source_status: str | None = None
    evidence_state: str = "not_evaluated"
    finding_count: int = 0
    evidence: list[ComplianceEvidenceItem] = Field(default_factory=list)


class ComplianceReportScope(BaseModel):
    since: str
    until: str
    control_count: int = 0
    finding_count: int = 0
    audit_event_count: int = 0
    # True when the audit window held more entries than the export cap; the
    # bundle then carries a partial (most-recent) set, not the full window.
    audit_events_truncated: bool = False
    audit_event_limit: int = 0
    completed_scan_count: int = 0


class ComplianceReportSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    passed: int = Field(alias="pass")
    warning: int = 0
    fail: int = 0
    incomplete: int = 0
    not_evaluated: int = 0
    score: float = 100.0


class ComplianceAuditIntegrity(BaseModel):
    verified: int = 0
    tampered: int = 0
    checked: int = 0
    # True when the checked set is a truncated (partial) view of the window.
    truncated: bool = False


class ComplianceThreatModel(BaseModel):
    integrity: str
    confidentiality: str
    replay: str
    non_repudiation: str


class ComplianceSignatureDisclosure(BaseModel):
    """Whether the bundle's own signature can be verified, and by whom."""

    # False when the deployment signs with a per-process HMAC key: the bundle
    # is stamped HMAC-SHA256 but no verifier — not even the issuer after a
    # restart — holds the key.
    signature_verifiable: bool
    persists_across_restart: bool
    # verifiable_public_key | verifiable_shared_secret | unverifiable_ephemeral_key
    verification_status: str
    verification_guidance: str
    # Operator action that makes evidence verifiable; null when it already is.
    remediation: str | None = None


class ComplianceReportBundle(BaseModel):
    schema_version: str = "v1"
    framework: str
    framework_key: str
    framework_label: str
    tenant_id: str
    generated_at: str
    expires_at: str
    nonce: str
    scope: ComplianceReportScope
    summary: ComplianceReportSummary
    controls: list[ComplianceReportControl] = Field(default_factory=list)
    audit_events: list[dict[str, Any]] = Field(default_factory=list)
    audit_log_integrity: ComplianceAuditIntegrity
    signature_algorithm: str
    # Inside the signed envelope: whether the signature is checkable at all.
    # A default deployment signs with a per-process HMAC key, so the algorithm
    # name alone overstates what the bundle proves.
    signature_disclosure: ComplianceSignatureDisclosure
    threat_model: ComplianceThreatModel
