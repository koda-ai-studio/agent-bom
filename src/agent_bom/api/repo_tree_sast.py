"""How a repository scan records a SAST pass that did not complete."""

from __future__ import annotations

from typing import Any

from agent_bom.scanners.state import record_coverage_warning
from agent_bom.security import sanitize_error


def sast_scan_error_data(exc: Any, sast_result_cls: Any) -> tuple[dict[str, Any], str]:
    known_reason_codes = {
        "invalid_semgrep_output",
        "offline_no_local_config",
        "offline_remote_config",
        "scan_failed",
        "semgrep_failed",
        "semgrep_unavailable",
    }
    reason_code = exc.reason_code if exc.reason_code in known_reason_codes else "scan_failed"
    detail_by_reason = {
        "offline_remote_config": "SAST skipped because offline mode disallows registry-backed rules.",
        "offline_no_local_config": "SAST skipped because offline mode found no local rule configuration.",
        "semgrep_unavailable": "SAST skipped because Semgrep is unavailable on the control plane.",
    }
    status_detail = detail_by_reason.get(reason_code)
    if status_detail is None:
        status_detail = sanitize_error(exc, generic=True)
    data = sast_result_cls(
        execution_status=exc.execution_status,
        status_reason=reason_code,
        status_detail=status_detail,
    ).to_dict()
    return data, reason_code


def record_sast_coverage_gap(reason_code: str, detail: str) -> None:
    """A source tree SAST did not cover is a coverage gap on the report, not only a warning line."""
    record_coverage_warning(
        {
            "ecosystem": "sast",
            "release": f"sast:{reason_code}",
            "reason": reason_code,
            "detail": detail or f"SAST did not run ({reason_code}).",
            "package_count": 0,
            "advisory_rows": 0,
        }
    )
