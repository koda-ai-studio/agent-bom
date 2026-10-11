"""Documented read contracts for scan polling and scan subresources."""

from typing import Any

from pydantic import RootModel

from agent_bom.api.read_models._base import ReadModel, ReadResponse
from agent_bom.domain.report_payloads import LicenseReportPayload, VexReportPayload


class ScanStatusResponse(ReadResponse):
    job_id: str
    graph_scan_id: str | None
    tenant_id: str
    batch_id: str | None
    correlation_cohort_id: str | None
    correlation_cohort_manifest_hash: str | None
    correlation_max_age_hours: int | None
    parent_job_id: str | None
    child_job_ids: list[str]
    target: dict[str, Any] | None
    target_index: int | None
    target_count: int | None
    source_id: str | None
    schedule_id: str | None
    status: str
    created_at: str
    completed_at: str | None
    request: dict[str, Any]
    summary: dict[str, Any] | None
    aggregation: dict[str, Any] | None
    auto_correlation: dict[str, Any] | None = None
    scan_timestamp: str | None
    generated_at: str | None
    scan_run: dict[str, Any] | None
    scan_outcome: str | None
    warning_count: int
    warnings_preview: list[Any]
    pushed: bool
    error: str | None


class ScannerCapabilities(ReadModel):
    scan_modes: list[str]
    required_scopes: list[str]
    permissions_used: list[str]
    outbound_destinations: list[str]
    data_boundary: str
    writes: bool
    network_access: bool
    guarantees: list[str]


class ScannerDriver(ReadModel):
    name: str
    module: str
    source: str
    phase: str
    execution_state: str
    failure_mode: str
    enabled_by_default: bool
    run_attr: str
    input_types: list[str]
    output_types: list[str]
    finding_types: list[str]
    skip_when: list[str]
    telemetry_keys: list[str]
    standards: list[str]
    summary: str
    capabilities: ScannerCapabilities


class ScannerSummary(ReadModel):
    total: int
    active: int
    passive: int
    planned: int
    by_phase: dict[str, int]
    by_state: dict[str, int]


class ScanDriversResponse(ReadResponse):
    drivers: list[ScannerDriver]
    summary: ScannerSummary
    warnings: list[str]


class ScanLicensesResponse(RootModel[LicenseReportPayload]):
    """The same license payload emitted in the report envelope."""


class ScanVexResponse(RootModel[VexReportPayload]):
    """The same VEX payload emitted in the report envelope."""
