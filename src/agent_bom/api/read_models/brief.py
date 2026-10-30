"""Executive summary composed from existing, independently scoped read contracts."""

from typing import Any, Literal

from agent_bom.api.read_models._base import IssueCounts, ReadModel, ReadResponse
from agent_bom.api.read_models.compliance import ComplianceSummaryResponse
from agent_bom.api.read_models.graph import GraphExposurePathsResponse
from agent_bom.api.read_models.posture import OverviewTopRisk, PostureResponse, TrendsResponse


class BriefLinks(ReadModel):
    evidence_pack: str
    verification_key: str
    findings: str
    exposure_paths: str


class ExecutiveBriefResponse(ReadResponse):
    schema_version: Literal["v1"]
    document_type: Literal["executive-brief"]
    tenant_id: str
    generated_at: str
    sample_data: bool
    posture: PostureResponse
    issues: IssueCounts
    remediation_priorities: list[OverviewTopRisk]
    exposure_paths: GraphExposurePathsResponse | None
    exposure_status: Literal["available", "unavailable"]
    compliance: ComplianceSummaryResponse
    scan_history: TrendsResponse
    scope: dict[str, Any]
    links: BriefLinks
    evidence_boundary: str
