"""Whole scan runs in the local analytics mirror are bounded by age and live bytes, not only by row counts."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.local_analytics import LocalAnalyticsStore

PADDING = "x" * 2048


def _days_ago(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _report(index: int, generated_at: str, findings: int = 30) -> dict:
    return {
        "scan_id": f"scan-{index}",
        "generated_at": generated_at,
        "findings": [
            {
                "id": f"finding-{index}-{finding}",
                "vulnerability_id": f"CVE-2026-{index:02d}{finding:04d}",
                "package_name": "fastapi",
                "package_version": "0.115.0",
                "ecosystem": "pypi",
                "severity": "high",
                "description": PADDING,
            }
            for finding in range(findings)
        ],
    }


@pytest.fixture
def no_row_caps(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "0")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_PACKAGES", "0")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_FINDINGS", "0")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_BYTES", "0")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS", "0")


def _ids(store: LocalAnalyticsStore) -> set[str]:
    return {row["scan_id"] for row in store.list_scan_runs(limit=50)}


def test_runs_older_than_the_age_cap_are_pruned_on_write(tmp_path, no_row_caps, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS", "30")
    store = LocalAnalyticsStore(tmp_path / "analytics.sqlite")

    store.record_scan_report(_report(0, _days_ago(100)), source="test")
    store.record_scan_report(_report(1, _days_ago(10)), source="test")
    store.record_scan_report(_report(2, _days_ago(0)), source="test")

    assert _ids(store) == {"scan-1", "scan-2"}


def test_the_newest_run_survives_the_age_cap(tmp_path, no_row_caps, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS", "30")
    store = LocalAnalyticsStore(tmp_path / "analytics.sqlite")

    store.record_scan_report(_report(0, _days_ago(400)), source="test")

    assert _ids(store) == {"scan-0"}


def test_non_positive_age_cap_disables_age_pruning(tmp_path, no_row_caps):
    store = LocalAnalyticsStore(tmp_path / "analytics.sqlite")

    store.record_scan_report(_report(0, _days_ago(400)), source="test")
    store.record_scan_report(_report(1, _days_ago(0)), source="test")

    assert _ids(store) == {"scan-0", "scan-1"}


def test_unparseable_timestamps_are_never_age_pruned(tmp_path, no_row_caps, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS", "30")
    store = LocalAnalyticsStore(tmp_path / "analytics.sqlite")

    store.record_scan_report(_report(0, "not-a-timestamp"), source="test")
    store.record_scan_report(_report(1, _days_ago(0)), source="test")

    assert _ids(store) == {"scan-0", "scan-1"}


def test_live_bytes_cap_prunes_oldest_runs_until_under_the_cap(tmp_path, no_row_caps, monkeypatch):
    control = LocalAnalyticsStore(tmp_path / "control.sqlite")
    for index in range(8):
        control.record_scan_report(_report(index, _days_ago(8 - index)), source="test")
    control_live = control.storage_stats()["live_bytes"]
    cap = control_live // 3
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_BYTES", str(cap))

    capped = LocalAnalyticsStore(tmp_path / "capped.sqlite")
    for index in range(8):
        capped.record_scan_report(_report(index, _days_ago(8 - index)), source="test")

    stats = capped.storage_stats()
    kept = _ids(capped)
    assert "scan-7" in kept
    assert 1 <= len(kept) <= 4
    assert stats["live_bytes"] < control_live
    assert stats["free_pages"] == 0
    assert stats["limits"]["bytes"] == cap


def test_storage_stats_report_live_bytes_and_oldest_run_age(tmp_path, no_row_caps, monkeypatch):
    store = LocalAnalyticsStore(tmp_path / "analytics.sqlite")
    store.record_scan_report(_report(0, _days_ago(100)), source="test")
    store.record_scan_report(_report(1, _days_ago(1)), source="test")

    stats = store.storage_stats()

    assert stats["limits"]["run_age_days"] == 0 and stats["limits"]["bytes"] == 0
    assert 99 <= stats["oldest_run_age_days"] <= 101
    assert 0 < stats["live_bytes"] <= stats["bytes"]
    assert stats["over_limit"] is False

    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS", "30")
    assert store.storage_stats()["over_limit"] is True


def test_report_prune_cli_takes_age_and_bytes_overrides(tmp_path, no_row_caps):
    store = LocalAnalyticsStore(tmp_path / "analytics.sqlite")
    store.record_scan_report(_report(0, _days_ago(100)), source="test")
    store.record_scan_report(_report(1, _days_ago(1)), source="test")

    aged = CliRunner().invoke(main, ["report", "prune", "--db", str(store.db_path), "--max-age-days", "30", "--format", "json"])
    sized = CliRunner().invoke(main, ["report", "prune", "--db", str(store.db_path), "--max-bytes", "1", "--format", "json"])
    unbounded = CliRunner().invoke(main, ["report", "prune", "--db", str(store.db_path), "--format", "json"])

    assert aged.exit_code == 0, aged.output
    assert json.loads(aged.output)["deleted_runs"] == 1
    assert sized.exit_code == 0, sized.output
    assert json.loads(sized.output)["deleted_runs"] == 1
    assert unbounded.exit_code == 0, unbounded.output
    assert json.loads(unbounded.output)["deleted_runs"] == 0
    assert _ids(store) == {"scan-0", "scan-1"}
