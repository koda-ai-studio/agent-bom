"""The CIS Foundations Benchmark line counts CIS benchmark checks only.

Databricks has no official CIS benchmark; its security checks are vendor best
practice (``CLOUD_BEST_PRACTICE_*`` findings). Folding them into the CIS
Foundations line reported fail 3 / error 2 for an AWS account with 2 failing
CIS checks and 1 unevaluable one.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.analytics_contract import VENDOR_BEST_PRACTICE_CLOUDS, build_cis_benchmark_check_rows
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes.compliance import _build_compliance

_AWS = {
    "benchmark_version": "3.0.0",
    "checks": [
        {"check_id": "1.4", "title": "Root key", "status": "FAIL", "severity": "critical"},
        {"check_id": "2.1.1", "title": "S3 HTTP", "status": "FAIL", "severity": "high"},
        {"check_id": "3.1", "title": "CloudTrail", "status": "ERROR", "severity": "high"},
        {"check_id": "1.5", "title": "Root MFA", "status": "PASS", "severity": "critical"},
    ],
}
_DATABRICKS = {
    "benchmark_version": "1.0",
    "checks": [
        {"check_id": "DBX-1", "title": "No table ACL", "status": "FAIL", "severity": "high"},
        {"check_id": "DBX-2", "title": "Token lifetime", "status": "ERROR", "severity": "medium"},
    ],
}


def _job(result: dict) -> ScanJob:
    now = datetime.now(timezone.utc).isoformat()
    return ScanJob(
        job_id="cloud", tenant_id="default", request=ScanRequest(), status=JobStatus.DONE, created_at=now, completed_at=now, result=result
    )


def test_databricks_best_practice_checks_stay_out_of_the_cis_foundations_line() -> None:
    payload = _build_compliance([_job({"scan_id": "cloud", "cis_benchmark": _AWS, "databricks_security": _DATABRICKS})])
    line = payload["cis_foundations_benchmark"]
    assert {k: line["summary"][k] for k in ("pass", "fail", "error")} == {"pass": 1, "fail": 2, "error": 1}
    assert "databricks" not in (line.get("providers") or {})


def test_vendor_best_practice_rows_remain_available_to_the_check_browser() -> None:
    rows = build_cis_benchmark_check_rows({"databricks_security": _DATABRICKS}, "cloud")
    assert {row["cloud"] for row in rows} == {"databricks"}
    assert "databricks" in VENDOR_BEST_PRACTICE_CLOUDS
