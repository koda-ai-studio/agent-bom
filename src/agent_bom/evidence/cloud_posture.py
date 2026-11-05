"""Cloud control evidence for scan grades, without turning missing checks into passes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_bom.evidence.cloud_scan import cloud_scan_scopes
from agent_bom.evidence.posture_dimensions import DimensionScore
from agent_bom.evidence.scan_run import ScanScopeStatus, serialized_coverage_view

BENCHMARK_FIELDS = (
    ("cis_benchmark_data", "cis_benchmark"),
    ("azure_cis_benchmark_data", "azure_cis_benchmark"),
    ("gcp_cis_benchmark_data", "gcp_cis_benchmark"),
    ("snowflake_cis_benchmark_data", "snowflake_cis_benchmark"),
    ("databricks_security_data", "databricks_security"),
)


@dataclass
class CloudPosture:
    present: bool = False
    passed: int = 0
    failed: int = 0
    unknown: int = 0
    incomplete: bool = False

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def score(self) -> float:
        return round(100 * self.passed / self.evaluated, 1) if self.evaluated else 0.0

    @property
    def summary(self) -> str:
        return f"{self.passed} passed, {self.failed} failed, {self.unknown} unevaluated cloud controls"

    def merge(self, other: CloudPosture) -> None:
        self.present |= other.present
        self.passed += other.passed
        self.failed += other.failed
        self.unknown += other.unknown
        self.incomplete |= other.incomplete


def cloud_posture(report: Any) -> CloudPosture:
    """Count actual check rows; summary counters cannot assert a clean assessment."""
    result = CloudPosture()
    for field, _ in BENCHMARK_FIELDS:
        payload = getattr(report, field, None)
        if payload is None:
            continue
        result.present = True
        if not isinstance(payload, Mapping):
            result.incomplete = True
            continue
        checks = payload.get("checks")
        if not isinstance(checks, list) or not checks:
            result.incomplete = True
            continue
        for check in checks:
            status = str(check.get("status", "")).upper() if isinstance(check, Mapping) else ""
            result.passed += status == "PASS"
            result.failed += status == "FAIL"
            if status not in {"PASS", "FAIL", "NOT_APPLICABLE"}:
                result.unknown += 1
                result.incomplete = True
        result.incomplete |= bool(payload.get("warnings") or payload.get("errored") or payload.get("no_data"))
        result.incomplete |= str(payload.get("status", "ok")).lower() not in {"ok", "complete"}
        result.incomplete |= str(payload.get("completeness", "complete")).lower() not in {"complete", "ok"}
    scopes = cloud_scan_scopes(report)
    for scope in scopes:
        result.present = True
        result.incomplete |= scope.status != ScanScopeStatus.COMPLETE
    run = getattr(report, "scan_run", None)
    for issue in getattr(run, "issues", []) or []:
        if getattr(issue, "code", "") == "cloud_collection_incomplete" and getattr(issue, "affects_coverage", True):
            result.present = result.incomplete = True
    return result


def serialized_cloud_fields(result: Mapping[str, Any]) -> dict[str, Any]:
    """Keep pushed/report JSON and in-process scorecards on the same evidence."""
    fields = {field: result.get(key, result.get(field)) for field, key in BENCHMARK_FIELDS}
    fields["cloud_inventory_data"] = result.get("cloud_inventory", result.get("cloud_inventory_data"))
    return fields


def serialized_cloud_posture(result: Mapping[str, Any]) -> CloudPosture:
    view = serialized_coverage_view(dict(result))
    for field, value in serialized_cloud_fields(result).items():
        setattr(view, field, value)
    return cloud_posture(view)


def apply_cloud_dimensions(cloud: CloudPosture, dimensions: dict[str, DimensionScore], *, has_inventory: bool) -> None:
    """Cloud controls replace tag-mapping coverage; absent non-cloud lanes stay unassessed."""
    if not cloud.present:
        return
    if not has_inventory:
        for dimension in dimensions.values():
            dimension.score, dimension.assessed = 0.0, False
            dimension.details = "Not assessed — no package or MCP evidence in this cloud scan"
    weight = dimensions["compliance_coverage"].weight
    dimensions["compliance_coverage"] = DimensionScore(
        name="Cloud Control Posture",
        score=cloud.score,
        weight=weight,
        details=cloud.summary + "; overall score cannot exceed the evaluated cloud control pass rate",
        assessed=bool(cloud.evaluated) and not cloud.incomplete,
    )
