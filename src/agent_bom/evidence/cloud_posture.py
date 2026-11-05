"""Cloud control evidence for scan grades, without turning missing checks into passes.

Score follows the common ``pass / (pass + fail + unknown)`` model: an errored or
unrecognized check is unknown and stays in the denominator because it cannot be
assumed fine; ``no_data`` and ``not_applicable`` controls are excluded from it.
Coverage is ``(pass + fail) / (pass + fail + unknown + no_data)``. See
``site-docs/reference/cloud-posture-grading.md``.
"""

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


# Below this share of applicable controls evaluated, a letter would describe too
# little of the account, so no grade is shown.
MIN_CONTROL_COVERAGE = 0.5

# Highest letter a partial assessment can earn. Unevaluated controls may hold
# failures, so the top band is reserved for a complete assessment.
PARTIAL_GRADE_CAP = "B"

# Providers whose collectors feed the benchmark fields above. Other connectors
# (model hubs, local runtimes) share the collector issue codes but not this grade.
_GRADED_PROVIDERS = frozenset({"aws", "azure", "gcp", "snowflake", "databricks"})
_PROVIDER_ISSUE_CODES = frozenset({"collector_failed", "collector_warning"})


@dataclass
class CloudPosture:
    present: bool = False
    passed: int = 0
    failed: int = 0
    unknown: int = 0
    no_data: int = 0
    not_applicable: int = 0
    incomplete: bool = False

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def applicable(self) -> int:
        return self.evaluated + self.unknown + self.no_data

    @property
    def coverage(self) -> float:
        return self.evaluated / self.applicable if self.applicable else 0.0

    @property
    def score(self) -> float:
        scored = self.evaluated + self.unknown
        return round(100 * self.passed / scored, 1) if scored else 0.0

    @property
    def partial(self) -> bool:
        return self.present and (self.incomplete or self.evaluated < self.applicable)

    @property
    def gradeable(self) -> bool:
        return self.evaluated > 0 and self.coverage >= MIN_CONTROL_COVERAGE

    @property
    def summary(self) -> str:
        return f"{self.passed} passed, {self.failed} failed, {self.unknown + self.no_data} unevaluated cloud controls"

    @property
    def ungraded_reason(self) -> str:
        if not self.evaluated:
            return "No cloud controls were evaluated — posture grade unavailable."
        return (
            f"Only {self.evaluated} of {self.applicable} applicable cloud controls were evaluated, "
            f"below the {MIN_CONTROL_COVERAGE:.0%} minimum — posture grade unavailable."
        )

    def cap_grade(self, grade: str) -> str:
        return PARTIAL_GRADE_CAP if self.partial and grade == "A" else grade

    def grade_label(self, grade: str) -> str:
        if not self.partial or grade == "N/A":
            return grade
        return f"{grade} (partial, {self.evaluated} of {self.applicable} evaluated)"

    def controls(self) -> dict[str, int | float]:
        return {
            "passed": self.passed,
            "failed": self.failed,
            "unknown": self.unknown,
            "no_data": self.no_data,
            "not_applicable": self.not_applicable,
            "evaluated": self.evaluated,
            "applicable": self.applicable,
            "coverage_percent": round(100 * self.coverage, 1),
        }

    def merge(self, other: CloudPosture) -> None:
        self.present |= other.present
        self.passed += other.passed
        self.failed += other.failed
        self.unknown += other.unknown
        self.no_data += other.no_data
        self.not_applicable += other.not_applicable
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
            result.no_data += status == "NO_DATA"
            result.not_applicable += status == "NOT_APPLICABLE"
            if status not in {"PASS", "FAIL", "NO_DATA", "NOT_APPLICABLE"}:
                result.unknown += 1
        result.incomplete |= bool(payload.get("warnings") or payload.get("errored") or payload.get("no_data"))
        result.incomplete |= str(payload.get("status", "ok")).lower() not in {"ok", "complete"}
        result.incomplete |= str(payload.get("completeness", "complete")).lower() not in {"complete", "ok"}
    scopes = cloud_scan_scopes(report)
    for scope in scopes:
        result.present = True
        result.incomplete |= scope.status != ScanScopeStatus.COMPLETE
    run = getattr(report, "scan_run", None)
    for issue in getattr(run, "issues", []) or []:
        if not getattr(issue, "affects_coverage", True):
            continue
        code = getattr(issue, "code", "")
        if code == "cloud_collection_incomplete":
            result.present = result.incomplete = True
        elif code in _PROVIDER_ISSUE_CODES and getattr(issue, "source", "") in _GRADED_PROVIDERS:
            # Marks graded controls as partial; a failed collector alone does not
            # turn a scan with local evidence into a cloud-graded one.
            result.incomplete = True
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
        details=cloud.summary + "; overall score cannot exceed the cloud control pass rate",
        assessed=cloud.gradeable,
    )
