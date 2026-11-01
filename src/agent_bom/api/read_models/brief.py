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


class BriefPriority(OverviewTopRisk):
    """An overview top risk plus the SLA presentation every brief consumer renders.

    ``sla_due_at`` stays the raw ISO timestamp for machines; ``sla_status`` and
    ``sla_policy`` are derived from it and from ``sla_due_at_source`` by one
    shared helper so the API, the MCP tool and the UI never disagree.
    """

    sla_status: Literal["overdue", "due_soon", "on_track", "unknown"] | None = None
    sla_policy: str | None = None


class ExecutiveBriefResponse(ReadResponse):
    schema_version: Literal["v1"]
    document_type: Literal["executive-brief"]
    tenant_id: str
    generated_at: str
    sample_data: bool
    posture: PostureResponse
    issues: IssueCounts
    remediation_priorities: list[BriefPriority]
    exposure_paths: GraphExposurePathsResponse | None
    exposure_status: Literal["available", "unavailable"]
    compliance: ComplianceSummaryResponse
    scan_history: TrendsResponse
    scope: dict[str, Any]
    links: BriefLinks
    evidence_boundary: str
