"""Stale advisory data never makes a scan's inventory look incomplete, so a fixed package leaves the current estate."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.api.finding_job_metadata import scan_collection_incomplete_reasons


def _job(outcome: str, issues: list[dict]) -> SimpleNamespace:
    return SimpleNamespace(result={"scan_run": {"outcome": outcome, "issues": issues, "scopes": []}})


_ADVISORY_WARNING = {
    "code": "scanner_warning",
    "stage": "scanning",
    "source": "vulnerability-data",
    "message": "advisory rows predate range-limit receipts; run agent-bom db update",
    "affects_coverage": True,
}


def test_advisory_data_warnings_alone_keep_the_inventory_authoritative() -> None:
    assert scan_collection_incomplete_reasons(_job("partial", [_ADVISORY_WARNING])) == []


def test_inventory_gaps_still_retain_prior_evidence() -> None:
    manifest_gap = {
        "code": "vulnerability_coverage_gap",
        "stage": "scanning",
        "source": "npm",
        "message": "npm:package.json: could not be parsed",
        "affects_coverage": True,
    }
    assert scan_collection_incomplete_reasons(_job("partial", [_ADVISORY_WARNING, manifest_gap])) != []
    assert scan_collection_incomplete_reasons(_job("partial", [])) == ["scan_partial"]
    assert "scan_failed" in scan_collection_incomplete_reasons(_job("failed", [_ADVISORY_WARNING]))
