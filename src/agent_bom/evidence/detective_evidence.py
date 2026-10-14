"""The scan evidence a report's detective controls are scored from.

See :mod:`agent_bom.evidence.control_modes` for why a detective control is
scored from the scan itself rather than from the findings mapped to it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent_bom.evidence.control_modes import detective_control_status, requires_vulnerability_coverage
from agent_bom.evidence.scan_run import vulnerability_coverage_incomplete

__all__ = ["DetectiveScanEvidence"]


@dataclass(frozen=True)
class DetectiveScanEvidence:
    """Completed-scan count, latest scan time, and whether the vulnerability lane was partial."""

    scan_count: int = 0
    latest_scan: str | None = None
    vulnerability_coverage_incomplete: bool = False

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
        return cls(
            scan_count=1 if has_findings else 0,
            latest_scan=generated_at.isoformat() if isinstance(generated_at, datetime) else None,
            vulnerability_coverage_incomplete=vulnerability_coverage_incomplete(report),
        )

    def control_status(self, tag_field: str, control_id: str) -> tuple[str, str]:
        """Score one detective control; a partial vulnerability lane only gates controls that rest on it."""
        return detective_control_status(
            scan_count=self.scan_count,
            latest_scan=self.latest_scan,
            vulnerability_coverage_incomplete=self.vulnerability_coverage_incomplete
            and requires_vulnerability_coverage(tag_field, control_id),
        )
