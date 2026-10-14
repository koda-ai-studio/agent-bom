"""The scan evidence a report's detective controls are scored from.

See :mod:`agent_bom.evidence.control_modes` for why a detective control is
scored from the scan itself rather than from the findings mapped to it. A
completed scan evidences a detective control only when the lane behind it ran:
the component inventory for CM-8 / CIS-02.1, the vulnerability lane for every
"identify vulnerabilities" control. An IaC-only, browser-only or ``--no-scan``
run evidences neither.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent_bom.evidence.control_modes import (
    LANE_INVENTORY,
    LANE_VULNERABILITY,
    _parse_timestamp,
    detective_control_status,
    detective_lane,
    requires_vulnerability_coverage,
)
from agent_bom.evidence.scan_run import (
    effective_scan_run,
    result_vulnerability_coverage_incomplete,
    serialized_coverage_view,
    vulnerability_coverage_incomplete,
    vulnerability_scan_skipped,
)

__all__ = ["DetectiveScanEvidence", "detective_lanes_evidenced", "result_detective_lanes"]

LaneScans = Mapping[str, tuple[int, "str | None"]]


def detective_lanes_evidenced(report: Any) -> frozenset[str]:
    """The detective lanes one report produced evidence for.

    The inventory lane ran when the report lists components. The vulnerability
    lane ran when the OSV lane recorded evaluated packages; reports that carry
    no performance block (API scans) fall back to "components were inventoried
    and not skipped". A ``--no-scan`` receipt always withholds the vulnerability
    lane.
    """
    inventoried = int(getattr(report, "total_packages", 0) or 0) > 0
    lanes = {LANE_INVENTORY} if inventoried else set()
    if vulnerability_scan_skipped(effective_scan_run(report)):
        return frozenset(lanes)
    performance = getattr(report, "scan_performance_data", None)
    osv = performance.get("osv") if isinstance(performance, dict) else None
    scanned = int(osv.get("packages_seen") or 0) > 0 if isinstance(osv, dict) else inventoried
    if scanned:
        lanes.add(LANE_VULNERABILITY)
    return frozenset(lanes)


def result_detective_lanes(result: Any) -> frozenset[str]:
    """:func:`detective_lanes_evidenced` over a serialized (JSON) scan result."""
    if not isinstance(result, dict):
        return frozenset()
    view = serialized_coverage_view(result)
    package_rows = {
        str(row["package"])
        for row in result.get("blast_radius") or []
        if isinstance(row, dict) and row.get("package") and str(row.get("finding_type") or "CVE") == "CVE"
    }
    view.total_packages = max(int(view.total_packages or 0), len(package_rows))
    return detective_lanes_evidenced(view)


@dataclass(frozen=True)
class DetectiveScanEvidence:
    """Completed-scan count, latest scan time, per-lane evidence, and whether the vulnerability lane was partial.

    ``lane_scans`` maps a lane to ``(scans that evidenced it, latest such scan)``.
    ``None`` means lanes were not derived and every completed scan counts.
    """

    scan_count: int = 0
    latest_scan: str | None = None
    vulnerability_coverage_incomplete: bool = False
    lane_scans: LaneScans | None = None

    @classmethod
    def for_report(cls, report: Any, *, has_findings: bool) -> DetectiveScanEvidence:
        """Derive the evidence from one report.

        ``scan_count`` uses the same conservative derivation as the narrative's
        nist_800_53_catalog line — a report carrying no findings is treated as no
        evidence, so an unmapped or unscanned estate reads not_evaluated rather
        than a fabricated pass, and the two representations in one narrative
        cannot contradict each other. ``generated_at`` may be absent on the
        lightweight shim the CLI rebuilds from a saved artifact; an unknown age is
        reported as unknown, never silently assumed fresh (see
        ``detective_control_status``).
        """
        generated_at = getattr(report, "generated_at", None)
        latest = generated_at.isoformat() if isinstance(generated_at, datetime) else None
        lanes = detective_lanes_evidenced(report) if has_findings else frozenset()
        return cls(
            scan_count=1 if has_findings else 0,
            latest_scan=latest,
            vulnerability_coverage_incomplete=vulnerability_coverage_incomplete(report),
            lane_scans={lane: (1, latest) for lane in lanes},
        )

    @classmethod
    def for_results(cls, scans: Iterable[tuple[Any, str | None]], *, latest_scan: str | None) -> DetectiveScanEvidence:
        """Derive the evidence from completed scans given as ``(serialized result, completed_at)``."""
        scans = list(scans)
        lane_times: dict[str, list[str | None]] = {LANE_INVENTORY: [], LANE_VULNERABILITY: []}
        for result, completed_at in scans:
            for lane in result_detective_lanes(result):
                lane_times[lane].append(completed_at)
        return cls(
            scan_count=len(scans),
            latest_scan=latest_scan,
            vulnerability_coverage_incomplete=any(result_vulnerability_coverage_incomplete(result) for result, _ in scans),
            lane_scans={lane: (len(times), _latest(times)) for lane, times in lane_times.items() if times},
        )

    def control_status(self, tag_field: str, control_id: str) -> tuple[str, str]:
        """Score one detective control from the scans whose lane evidences it.

        A partial vulnerability lane only gates controls that rest on it.
        """
        scan_count, latest_scan = self.scan_count, self.latest_scan
        if self.lane_scans is not None and scan_count > 0:
            scan_count, latest_scan = self.lane_scans.get(detective_lane(tag_field, control_id), (0, None))
            if scan_count == 0:
                return "not_assessed", "detective_evidence_not_collected"
        return detective_control_status(
            scan_count=scan_count,
            latest_scan=latest_scan,
            vulnerability_coverage_incomplete=self.vulnerability_coverage_incomplete
            and requires_vulnerability_coverage(tag_field, control_id),
        )


def _latest(times: list[str | None]) -> str | None:
    """The most recent parseable timestamp; an undatable scan never outranks a dated one."""
    dated = [(parsed, value) for value in times if value and (parsed := _parse_timestamp(value)) is not None]
    if dated:
        return max(dated)[1]
    return next((value for value in times if value), None)
