"""Persisted AI advice is tenant-scoped on every store that holds it."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.api.ai_assessment_store import InMemoryAIAssessmentStore, SQLiteAIAssessmentStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "memory":
        return InMemoryAIAssessmentStore()
    return SQLiteAIAssessmentStore(str(tmp_path / "ai.db"))


def _assessment(finding_id: str, verdict: str = "confirmed") -> dict:
    return {"finding_id": finding_id, "verdict": verdict, "rationale": "because", "provenance": {"model": "ollama/m"}}


def test_latest_scan_wins_per_finding(store) -> None:
    store.put_scan(
        "t1", "scan-1", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("a", "needs_review"), _assessment("b")]
    )
    store.put_scan("t1", "scan-2", {"status": "ok", "created_at": "2026-11-02T00:00:00+00:00"}, [_assessment("a", "confirmed")])
    latest = store.latest_for_findings("t1", ["a", "b", "missing"])
    assert set(latest) == {"a", "b"}
    assert latest["a"]["verdict"] == "confirmed"
    assert latest["a"]["scan_id"] == "scan-2"
    assert latest["b"]["scan_id"] == "scan-1"


def test_no_tenant_reads_another_tenants_assessments(store) -> None:
    store.put_scan("t1", "scan-1", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("shared-id")])
    assert store.latest_for_findings("t2", ["shared-id"]) == {}
    assert store.latest_run("t2") is None


def test_same_scan_and_finding_ids_stay_separate_between_tenants(store) -> None:
    store.put_scan("t1", "same-scan", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("x", "confirmed")])
    store.put_scan("t2", "same-scan", {"status": "failed", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("x", "needs_review")])
    assert store.latest_for_findings("t1", ["x"])["x"]["verdict"] == "confirmed"
    assert store.latest_for_findings("t2", ["x"])["x"]["verdict"] == "needs_review"
    assert store.latest_run("t1")["status"] == "ok"
    assert store.latest_run("t2")["status"] == "failed"


def test_rerun_of_a_scan_replaces_its_rows(store) -> None:
    store.put_scan("t1", "scan-1", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("a"), _assessment("b")])
    store.put_scan("t1", "scan-1", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("a")])
    assert set(store.latest_for_findings("t1", ["a", "b"])) == {"a"}


def test_latest_run_reports_the_newest_scan(store) -> None:
    store.put_scan("t1", "old", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [])
    store.put_scan("t1", "new", {"status": "failed", "created_at": "2026-11-03T00:00:00+00:00"}, [])
    run = store.latest_run("t1")
    assert run["status"] == "failed" and run["scan_id"] == "new"


def test_delete_scan_and_tenant_purge(store) -> None:
    store.put_scan("t1", "s1", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("a")])
    store.put_scan("t1", "s2", {"status": "ok", "created_at": "2026-11-02T00:00:00+00:00"}, [_assessment("b")])
    store.put_scan("t2", "s1", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("a")])
    assert store.delete_scan("t1", "s1") >= 1
    assert set(store.latest_for_findings("t1", ["a", "b"])) == {"b"}
    assert store.purge_tenant("t1") >= 1
    assert store.latest_for_findings("t1", ["b"]) == {}
    assert store.latest_run("t1") is None
    assert set(store.latest_for_findings("t2", ["a"])) == {"a"}


def test_ttl_sweep_expires_rows_with_their_scans(store) -> None:
    store.put_scan("t1", "old", {"status": "ok", "created_at": "2026-01-01T00:00:00+00:00"}, [_assessment("a")])
    store.put_scan("t2", "new", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_assessment("b")])
    assert store.delete_older_than("2026-06-01T00:00:00+00:00") == 2
    assert store.latest_for_findings("t1", ["a"]) == {} and store.latest_run("t1") is None
    assert set(store.latest_for_findings("t2", ["b"])) == {"b"}


def test_empty_lookup_touches_nothing(store) -> None:
    assert store.latest_for_findings("t1", []) == {}
