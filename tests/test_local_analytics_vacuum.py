"""The local analytics mirror returns pruned pages to the OS instead of growing a freelist forever."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.local_analytics import LocalAnalyticsStore

PADDING = "x" * 2048


def _report(index: int, findings: int = 300) -> dict:
    return {
        "scan_id": f"scan-{index}",
        "generated_at": f"2026-05-{index + 1:02d}T16:00:00+00:00",
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


def _pragma(path: Path, name: str) -> int:
    with sqlite3.connect(str(path)) as conn:
        return int(conn.execute(f"PRAGMA {name}").fetchone()[0])


def _legacy_database(path: Path) -> Path:
    """A file whose header was written before the store ever opened it (auto_vacuum=0)."""
    with sqlite3.connect(str(path)) as conn:
        conn.execute("CREATE TABLE legacy_marker (id INTEGER PRIMARY KEY)")
    return path


@pytest.fixture
def small_caps(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "2")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_PACKAGES", "0")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_FINDINGS", "0")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS", "0")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_BYTES", "0")


def test_new_database_is_created_in_incremental_auto_vacuum_mode(tmp_path):
    path = tmp_path / "analytics.sqlite"

    LocalAnalyticsStore(path).storage_stats()

    assert _pragma(path, "auto_vacuum") == 2
    with sqlite3.connect(str(path)) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_existing_database_keeps_its_mode_until_compacted(tmp_path):
    path = _legacy_database(tmp_path / "analytics.sqlite")
    store = LocalAnalyticsStore(path)

    stats = store.storage_stats()

    assert _pragma(path, "auto_vacuum") == 0
    assert stats["auto_vacuum"] == "none"

    store.prune(apply=True, compact=True)

    assert _pragma(path, "auto_vacuum") == 2
    assert store.storage_stats()["auto_vacuum"] == "incremental"


def test_write_path_prune_releases_pages_on_a_new_database(tmp_path, small_caps):
    fresh = LocalAnalyticsStore(tmp_path / "fresh.sqlite")
    legacy = LocalAnalyticsStore(_legacy_database(tmp_path / "legacy.sqlite"))

    for index in range(6):
        fresh.record_scan_report(_report(index), source="test")
        legacy.record_scan_report(_report(index), source="test")

    assert len(fresh.list_scan_runs(limit=10)) == 2 == len(legacy.list_scan_runs(limit=10))
    assert _pragma(fresh.db_path, "freelist_count") == 0
    assert _pragma(legacy.db_path, "freelist_count") > 0
    assert _pragma(fresh.db_path, "page_count") < _pragma(legacy.db_path, "page_count")


def test_storage_stats_expose_free_pages_and_bytes(tmp_path, small_caps):
    store = LocalAnalyticsStore(_legacy_database(tmp_path / "legacy.sqlite"))
    for index in range(6):
        store.record_scan_report(_report(index), source="test")

    stats = store.storage_stats()

    assert stats["free_pages"] == _pragma(store.db_path, "freelist_count") > 0
    assert stats["page_size"] == _pragma(store.db_path, "page_size")
    assert stats["free_bytes"] == stats["free_pages"] * stats["page_size"]
    assert stats["auto_vacuum"] == "none"


def test_prune_result_reports_free_bytes_before_and_after_compaction(tmp_path, small_caps):
    store = LocalAnalyticsStore(_legacy_database(tmp_path / "legacy.sqlite"))
    for index in range(6):
        store.record_scan_report(_report(index), source="test")

    preview = store.prune()
    assert preview["free_bytes_before"] > 0
    assert preview["free_bytes_after"] == preview["free_bytes_before"]

    compacted = store.prune(apply=True, compact=True)
    assert compacted["free_bytes_before"] > 0
    assert compacted["free_bytes_after"] == 0


def test_report_storage_shows_free_bytes_and_compaction_hint(tmp_path, small_caps):
    store = LocalAnalyticsStore(_legacy_database(tmp_path / "legacy.sqlite"))
    for index in range(6):
        store.record_scan_report(_report(index), source="test")

    table = CliRunner().invoke(main, ["report", "storage", "--db", str(store.db_path)])
    as_json = CliRunner().invoke(main, ["report", "storage", "--db", str(store.db_path), "--format", "json"])

    assert table.exit_code == 0, table.output
    assert "free bytes" in table.output
    assert "agent-bom report prune --apply --compact" in table.output
    payload = json.loads(as_json.output)
    assert payload["free_bytes"] > 0 and payload["free_pages"] > 0


def test_report_prune_shows_free_bytes_and_hint_until_compacted(tmp_path, small_caps):
    store = LocalAnalyticsStore(_legacy_database(tmp_path / "legacy.sqlite"))
    for index in range(6):
        store.record_scan_report(_report(index), source="test")

    preview = CliRunner().invoke(main, ["report", "prune", "--db", str(store.db_path)])
    assert preview.exit_code == 0, preview.output
    assert "Free:" in preview.output
    assert "--apply --compact" in preview.output

    compacted = CliRunner().invoke(main, ["report", "prune", "--db", str(store.db_path), "--apply", "--compact"])
    assert compacted.exit_code == 0, compacted.output
    assert "Free:" in compacted.output
    assert "--apply --compact" not in compacted.output
