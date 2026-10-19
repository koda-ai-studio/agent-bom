"""Findings report format and request scope."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_bom.finding_scope import FindingClass, FindingSeverityFilter, canonical_finding_severity_filter


class ReportFormat(str, Enum):
    """Supported async report artifact formats."""

    NDJSON = "ndjson"


class ReportJobRequest(BaseModel):
    """Request body for POST /v1/reports, including the canonical lane scope."""

    model_config = ConfigDict(extra="forbid")

    format: ReportFormat = ReportFormat.NDJSON
    sort: Literal["effective_reach", "cvss", "severity", "ordinal"] = "effective_reach"
    severity: FindingSeverityFilter | None = None
    q: str | None = Field(default=None, max_length=256)
    scan_id: str | None = Field(default=None, max_length=128)
    provider: str | None = Field(default=None, max_length=64)
    account: str | None = Field(default=None, max_length=256)
    environment: str | None = Field(default=None, max_length=64)
    domain: str | None = Field(default=None, max_length=32)
    owner: str | None = Field(default=None, max_length=256)
    sla: Literal["overdue", "due", "unassigned"] | None = None
    lane: str | None = Field(default=None, max_length=32)
    finding_class: FindingClass | None = None
    status: Literal["open", "resolved", "all"] = "open"
    window_days: int | None = Field(default=None, ge=0, le=3650)

    @field_validator("severity", mode="before")
    @classmethod
    def _canonicalize_severity(cls, value: object) -> str | None:
        return canonical_finding_severity_filter(value)
