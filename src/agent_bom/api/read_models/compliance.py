"""Typed OpenAPI contracts for the compliance, CIS benchmark and posture read routes."""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import CountMetadata, Num, ReadModel, ReadResponse

# ── CIS benchmark ────────────────────────────────────────────────────────────


class CisChecksResponse(ReadResponse):
    checks: list[dict[str, Any]]
    count: int
    source: str


class CisTrendsResponse(ReadResponse):
    buckets: list[dict[str, Any]]
    count: int
    source: str
    bucket: str
    days: int


# ── framework posture ────────────────────────────────────────────────────────


class AisvsComplianceResponse(ReadResponse):
    benchmark: dict[str, Any]
    framework: str
    framework_key: str
    framework_label: str
    measured_at: str | None
    representation: str
    scan_id: str | None
    score: Num
    source: str
    summary: dict[str, Num]


class FrameworkComplianceResponse(ReadResponse):
    """Per-framework posture; the ``aisvs`` slug answers with the benchmark shape."""

    framework: str
    score: Num
    summary: dict[str, Num]
    controls: list[dict[str, Any]] | None = None
    evaluated_controls: int | None = None
    status: str | None = None
    total_controls: int | None = None
    benchmark: dict[str, Any] | None = None
    framework_key: str | None = None
    framework_label: str | None = None
    # Distinct findings that are control evidence for the framework: the /v1/findings?framework= total.
    finding_count: int | None = None
    finding_count_basis: str | None = None
    measured_at: str | None = None
    representation: str | None = None
    scan_id: str | None = None
    source: str | None = None


class ComplianceSummaryResponse(ReadResponse):
    evaluated_controls: int
    frameworks: dict[str, dict[str, Any]]
    has_agent_context: bool
    has_mcp_context: bool
    latest_scan: str | None
    overall_score: Num
    overall_status: str
    scan_count: int
    scan_sources: list[str]
    summary: dict[str, Num]
    total_controls: int


class Nist80053DrillResponse(ReadResponse):
    controls: list[dict[str, Any]]
    families: list[dict[str, Any]]
    framework: str
    framework_key: str
    framework_label: str
    iso_27001_derived: Any
    representation: str
    score: Num
    source: str
    status: str
    summary: dict[str, Num]
    vendor_asserted: bool


class ComplianceVerificationKeyResponse(ReadResponse):
    algorithm: str
    key_distribution: str
    key_id: str | None
    persists_across_restart: bool
    public_key_pem: str | None
    remediation: str | None
    signature_verifiable: bool
    verification_status: str


class EvidencePackScope(ReadModel):
    audit_event_count: int
    audit_event_limit: int
    audit_events_truncated: bool
    completed_scan_count: int
    control_count: int
    distinct_finding_count: int
    evidence_row_count: int
    framework_count: int
    since: str
    until: str


class AuditLogIntegrity(ReadModel):
    checked: int
    tampered: int
    truncated: bool
    verified: int


class ComplianceEvidencePackResponse(ReadResponse):
    """Signed multi-framework evidence pack (served as a JSON attachment)."""

    audit_events: list[dict[str, Any]]
    audit_log_integrity: AuditLogIntegrity
    document_type: str
    expires_at: str
    frameworks: list[dict[str, Any]]
    generated_at: str
    nonce: str
    schema_version: str
    scope: EvidencePackScope
    signature: str
    signature_algorithm: str
    signature_disclosure: dict[str, Any]
    signature_key_id: str | None = None
    signature_public_key_pem: str | None = None
    summary: dict[str, Num | None]
    tenant_id: str


# ── compliance hub ───────────────────────────────────────────────────────────


class HubFindingsResponse(ReadResponse):
    count: int
    count_metadata: CountMetadata
    cursor: str
    filters: dict[str, Any]
    findings: list[dict[str, Any]]
    has_more: bool
    limit: int
    next_cursor: str
    offset: int
    scan_id: str | None
    schema_version: str
    sort: str
    total: int | None
    warnings: list[Any]


# ── posture ──────────────────────────────────────────────────────────────────


class EnrichmentPostureResponse(ReadResponse):
    operator_message: str
    sources: list[dict[str, Any]]
    status: str


class BackpressurePostureResponse(ReadResponse):
    enabled: bool
    notes: str
    paths: list[dict[str, Any]]
    status: str


class CredentialRiskRankingResponse(ReadResponse):
    count: int
    credentials: list[dict[str, Any]]
    rotation_governance: dict[str, Any]


class IncidentCorrelationResponse(ReadResponse):
    count: int
    incidents: list[Any]
