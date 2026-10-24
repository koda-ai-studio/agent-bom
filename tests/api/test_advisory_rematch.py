"""Daily re-match of stored inventory against advisories updated since a cursor."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api import advisory_rematch as rematch
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.operator_advisory_store import InMemoryOperatorAdvisoryStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store, set_operator_advisory_store
from agent_bom.scanners.operator_advisory import OperatorAdvisory

ADVISORY = json.loads((Path(__file__).parents[1] / "fixtures" / "php2shell" / "operator-advisory.json").read_text())
NOW = datetime(2026, 10, 23, 6, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 10, 24, 6, 0, tzinfo=timezone.utc)


def _job(tenant: str, name: str, version: str, ecosystem: str = "generic", completed: str = "2026-10-20T00:01:00+00:00") -> ScanJob:
    package = {"name": name, "version": version, "ecosystem": ecosystem}
    return ScanJob(
        job_id=f"job-{tenant}-{name}",
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=completed,
        completed_at=completed,
        request=ScanRequest(images=[f"{tenant}/{name}:{version}"]),
        result={"scan_id": f"scan-{tenant}", "agents": [{"name": "img", "mcp_servers": [{"name": name, "packages": [package]}]}]},
    )


def _feed_advisory(published: str = "2026-10-22T00:00:00+00:00") -> OperatorAdvisory:
    return rematch.feed_advisory(
        advisory_id="GHSA-feed-0001",
        aliases=["CVE-2026-55555"],
        summary="feed-published flaw",
        severity="high",
        published=published,
        affected=[("npm", "left-pad", "1.0.0", "1.3.1", None, "")],
    )


class _Feed:
    def __init__(self, advisories: list[OperatorAdvisory], modified: str | None = "2026-10-22T12:00:00+00:00") -> None:
        self.advisories, self.modified, self.cursors = advisories, modified, []

    def __call__(self, cursor: str | None, after_id: str | None = None) -> rematch.FeedBatch:
        self.cursors.append(cursor)
        return rematch.FeedBatch(self.advisories, self.modified)


def _failing_feed(cursor: str | None, after_id: str | None = None) -> rematch.FeedBatch:
    raise rematch.FeedUnavailableError("local vulnerability DB missing")


@pytest.fixture()
def env():
    jobs = InMemoryJobStore()
    for job in (_job("tenant-a", "php", "8.3.30"), _job("tenant-a", "left-pad", "1.2.0", "npm"), _job("tenant-b", "php", "8.3.30")):
        jobs.put(job)
    set_job_store(jobs)
    store = InMemoryOperatorAdvisoryStore()
    set_operator_advisory_store(store)
    rematch.reset_process_status()
    yield store
    set_operator_advisory_store(None)
    rematch.reset_process_status()


def test_rematch_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_ADVISORY_REMATCH", raising=False)
    assert rematch.rematch_enabled() is False
    monkeypatch.setenv("AGENT_BOM_ADVISORY_REMATCH", "1")
    assert rematch.rematch_enabled() is True
    monkeypatch.setenv("AGENT_BOM_ADVISORY_REMATCH_INTERVAL_SECONDS", "5")
    assert rematch.rematch_interval_seconds() == rematch.MIN_INTERVAL_SECONDS


def test_cursor_advances_after_complete_run_and_findings_are_stamped(env: InMemoryOperatorAdvisoryStore) -> None:
    env.put("tenant-a", ADVISORY)
    feed = _Feed([_feed_advisory()])
    status = rematch.run_tenant_rematch("tenant-a", feed_source=feed, now=NOW)
    assert status["status"] == "complete"
    assert status["new_findings"] == 2
    state = env.get_rematch_state("tenant-a")
    assert state["feed_cursor"] == "2026-10-22T12:00:00+00:00"
    assert state["operator_cursor"] == NOW.isoformat()
    by_id = {f["advisory_id"]: f for f in state["recent_findings"]}
    assert by_id["CVE-2026-109618"]["provenance"] == "operator_advisory"
    assert by_id["GHSA-feed-0001"]["provenance"] == "feed"
    assert by_id["GHSA-feed-0001"]["fixed_version"] == "1.3.1"
    for finding in by_id.values():
        assert finding["first_seen"] == NOW.isoformat()
        assert finding["new_since_published"] is True

    rematch.run_tenant_rematch("tenant-a", feed_source=feed, now=LATER)
    assert feed.cursors == [None, "2026-10-22T12:00:00+00:00"]


def test_scan_after_publication_is_not_new_since_published(env: InMemoryOperatorAdvisoryStore) -> None:
    rematch.run_tenant_rematch("tenant-a", feed_source=_Feed([_feed_advisory(published="2026-10-01T00:00:00+00:00")]), now=NOW)
    (finding,) = env.get_rematch_state("tenant-a")["recent_findings"]
    assert finding["new_since_published"] is False


def test_unreachable_feed_fails_closed_and_keeps_cursor(env: InMemoryOperatorAdvisoryStore) -> None:
    env.put_rematch_state("tenant-a", {"feed_cursor": "2026-10-01T00:00:00+00:00", "operator_cursor": "2026-10-01T00:00:00+00:00"})
    env.put("tenant-a", ADVISORY)
    status = rematch.run_tenant_rematch("tenant-a", feed_source=_failing_feed, now=NOW)
    assert status == {**status, "status": "incomplete", "reason": "feed_unavailable", "new_findings": 0}
    state = env.get_rematch_state("tenant-a")
    assert state["feed_cursor"] == "2026-10-01T00:00:00+00:00"
    assert state["operator_cursor"] == "2026-10-01T00:00:00+00:00"
    assert state.get("recent_findings", []) == []
    assert state["last_run"]["status"] == "incomplete"


def test_unreachable_store_fails_closed(env: InMemoryOperatorAdvisoryStore, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_tenant: str) -> list:
        raise OSError("store offline")

    monkeypatch.setattr(env, "list", broken)
    status = rematch.run_tenant_rematch("tenant-a", feed_source=_Feed([]), now=NOW)
    assert (status["status"], status["reason"]) == ("incomplete", "store_unavailable")
    assert (env.get_rematch_state("tenant-a") or {}).get("feed_cursor") is None


def test_repeat_runs_do_not_duplicate_findings(env: InMemoryOperatorAdvisoryStore) -> None:
    env.put("tenant-a", ADVISORY)
    feed = _Feed([_feed_advisory()])
    rematch.run_tenant_rematch("tenant-a", feed_source=feed, now=NOW)
    env.put("tenant-a", ADVISORY)  # re-declared: updated since the cursor, matched again
    second = rematch.run_tenant_rematch("tenant-a", feed_source=feed, now=LATER)
    assert second["status"] == "complete"
    assert second["new_findings"] == 0
    findings = env.get_rematch_state("tenant-a")["recent_findings"]
    assert len(findings) == 2
    assert {f["first_seen"] for f in findings} == {NOW.isoformat()}


def test_run_once_is_tenant_scoped(env: InMemoryOperatorAdvisoryStore) -> None:
    env.put("tenant-a", ADVISORY)
    summary = rematch.run_rematch_once(feed_source=_Feed([]), now=NOW)
    assert summary["tenants_examined"] == 2
    assert summary["status"] == "complete"
    assert [f["advisory_id"] for f in env.get_rematch_state("tenant-a")["recent_findings"]] == ["CVE-2026-109618"]
    assert env.get_rematch_state("tenant-b")["recent_findings"] == []


def test_status_surfaces_on_health_and_tenant_listing(env: InMemoryOperatorAdvisoryStore) -> None:
    from agent_bom.api.server import app

    client = TestClient(app)
    assert client.get("/v1/system/health").json()["advisory_rematch"]["last_run_status"] == "never"
    rematch.run_rematch_once(feed_source=_failing_feed, now=NOW)
    health = client.get("/v1/system/health").json()["advisory_rematch"]
    assert health == {**health, "enabled": False, "last_run_status": "incomplete", "tenants_examined": 2, "incomplete_tenants": 2}
    assert "tenant-a" not in json.dumps(health)
    listing = client.get("/v1/intel/operator-advisories").json()
    assert "rematch" in listing


def test_local_feed_reader_honours_cursor_and_fails_closed_without_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.db import schema

    db = tmp_path / "vulns.db"
    monkeypatch.setattr(schema, "DB_PATH", db)
    with pytest.raises(rematch.FeedUnavailableError):
        rematch.local_feed_advisories_since(None)
    conn = schema.init_db(db)
    for vid, modified in (("GHSA-old", "2026-10-01T00:00:00Z"), ("GHSA-new", "2026-10-22T00:00:00Z")):
        conn.execute(
            "INSERT INTO vulns (id, summary, severity, aliases, published, modified, source) "
            "VALUES (?, 's', 'high', 'CVE-2026-1', ?, ?, 'osv')",
            (vid, modified, modified),
        )
        conn.execute(
            "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed) VALUES (?, 'npm', 'left-pad', '0', '1.3.1')", (vid,)
        )
    conn.commit()
    conn.close()
    batch = rematch.local_feed_advisories_since("2026-10-10T00:00:00Z")
    assert [a.id for a in batch.advisories] == ["GHSA-new"]
    assert batch.newest_modified == "2026-10-22T00:00:00Z"
    assert batch.advisories[0].affected[0].ranges[0].fixed == "1.3.1"
    assert batch.newest_id == "GHSA-new"
    assert rematch.local_feed_advisories_since(batch.newest_modified, batch.newest_id).advisories == []
    # A cursor written before the keyset re-reads its own timestamp once; ``seen`` dedupes the repeat.
    assert [a.id for a in rematch.local_feed_advisories_since("2026-10-22T00:00:00Z").advisories] == ["GHSA-new"]


def _feed_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str, str, str, str, str]]) -> None:
    """rows: (id, modified, package, introduced, fixed, limit_version)."""
    from agent_bom.db import schema

    db = tmp_path / "vulns.db"
    monkeypatch.setattr(schema, "DB_PATH", db)
    conn = schema.init_db(db)
    conn.executemany(
        "INSERT INTO vulns (id, summary, severity, published, modified, source) VALUES (?, 's', 'high', ?, ?, 'osv')",
        [(vid, modified, modified) for vid, modified, *_ in rows],
    )
    conn.executemany(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected, limit_version) "
        "VALUES (?, 'npm', ?, ?, ?, '', ?)",
        [(vid, package, introduced, fixed, limit) for vid, _, package, introduced, fixed, limit in rows],
    )
    conn.commit()
    conn.close()


def test_feed_cursor_never_skips_records_sharing_the_boundary_timestamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tie = "2026-10-23T00:00:00Z"
    total = rematch.MAX_FEED_ADVISORIES + 1
    _feed_db(tmp_path, monkeypatch, [(f"GHSA-tie-{i:05d}", tie, "left-pad", "0", "1.0.0", "") for i in range(total)])
    seen: set[str] = set()
    cursor, after = "2026-10-22T00:00:00Z", None
    for _ in range(3):
        batch = rematch.local_feed_advisories_since(cursor, after)
        seen |= {advisory.id for advisory in batch.advisories}
        cursor, after = batch.newest_modified or cursor, batch.newest_id or after
    assert len(seen) == total
    assert f"GHSA-tie-{total - 1:05d}" in seen


def test_rematch_run_persists_a_keyset_cursor_and_resumes_inside_a_timestamp_tie(
    env: InMemoryOperatorAdvisoryStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tie = "2026-10-23T00:00:00Z"
    total = rematch.MAX_FEED_ADVISORIES + 1
    rows = [(f"GHSA-tie-{i:05d}", tie, "left-pad-none", "0", "1.0.0", "") for i in range(total - 1)]
    _feed_db(tmp_path, monkeypatch, [*rows, (f"GHSA-tie-{total - 1:05d}", tie, "left-pad", "0", "9.0.0", "")])
    env.put_rematch_state("tenant-a", {"feed_cursor": "2026-10-22T00:00:00Z", "operator_cursor": NOW.isoformat()})
    rematch.run_tenant_rematch("tenant-a", now=NOW)
    state = env.get_rematch_state("tenant-a")
    assert (state["feed_cursor"], state["feed_cursor_id"]) == (tie, f"GHSA-tie-{total - 2:05d}")
    rematch.run_tenant_rematch("tenant-a", now=LATER)
    assert [f["advisory_id"] for f in env.get_rematch_state("tenant-a")["recent_findings"]] == [f"GHSA-tie-{total - 1:05d}"]


@pytest.mark.parametrize(("version", "matched"), [("8.5.1", False), ("7.4.0", True)])
def test_feed_rematch_honours_the_exclusive_range_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str, matched: bool
) -> None:
    from agent_bom.scanners.operator_advisory import match_advisories_against_reports

    _feed_db(tmp_path, monkeypatch, [("GHSA-limit-0001", "2026-10-23T00:00:01Z", "jsonwebtoken", "0", "", "8.0.0")])
    batch = rematch.local_feed_advisories_since("2026-10-22T00:00:00Z")
    report = {"scan_id": "s1", "agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [
        {"name": "jsonwebtoken", "version": version, "ecosystem": "npm"}]}]}]}  # fmt: skip
    result = match_advisories_against_reports(batch.advisories, [report], provenance="feed")
    assert result.complete
    assert [f["advisory_id"] for f in result.findings] == (["GHSA-limit-0001"] if matched else [])


def test_feed_and_scan_time_range_verdicts_agree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The re-match path and the scan-time lookup classify the same rows identically."""
    from agent_bom.core.versions.osv import version_match_state
    from agent_bom.scanners.operator_advisory import _in_range

    cases = [
        ("1.2.0", "0", "1.3.1", "", ""),
        ("8.5.1", "0", "", "", "8.0.0"),
        ("2.0.0", "1.0.0", "", "2.0.0", ""),
        ("0.9", "1.0", "2.0", "", ""),
    ]
    for version, introduced, fixed, last, limit in cases:
        advisory = rematch.feed_advisory(
            advisory_id="GHSA-x-1", aliases=[], summary="s", severity="high", published=None,
            affected=[("npm", "p", introduced, fixed, last, limit)],
        )  # fmt: skip
        verdict = _in_range(version, advisory.affected[0].ranges[0], "npm")
        assert verdict is {"affected": True, "unaffected": False}[version_match_state(version, introduced, fixed, last, "npm", limit)]


def test_tenant_cap_marks_the_run_truncated_and_counts_the_skipped(env: InMemoryOperatorAdvisoryStore, monkeypatch) -> None:
    from agent_bom.api.server import app

    monkeypatch.setattr(rematch, "MAX_TENANTS_PER_RUN", 1)
    summary = rematch.run_rematch_once(feed_source=_Feed([]), now=NOW)
    assert summary == {**summary, "status": "incomplete", "tenants_examined": 1, "tenants_skipped": 1, "truncated": True}
    health = TestClient(app).get("/v1/system/health").json()["advisory_rematch"]
    assert health == {**health, "last_run_status": "incomplete", "tenants_skipped": 1, "truncated": True, "job_cap_reached": False}
    assert "tenant-b" not in json.dumps(health)
    skipped = env.get_rematch_state("tenant-b")
    assert skipped["last_run"] == {**skipped["last_run"], "status": "incomplete", "reason": "tenant_cap"}
    assert skipped.get("feed_cursor") is None


def test_job_cap_marks_the_run_truncated(env: InMemoryOperatorAdvisoryStore, monkeypatch) -> None:
    monkeypatch.setattr(rematch, "MAX_JOBS_SCANNED", 2)
    summary = rematch.run_rematch_once(feed_source=_Feed([]), now=NOW)
    assert summary == {**summary, "status": "incomplete", "job_cap_reached": True, "truncated": True}


def test_uncapped_run_reports_not_truncated(env: InMemoryOperatorAdvisoryStore) -> None:
    summary = rematch.run_rematch_once(feed_source=_Feed([]), now=NOW)
    assert summary == {**summary, "status": "complete", "tenants_skipped": 0, "job_cap_reached": False, "truncated": False}


def _reached_per_run(runs: int, cap: int, monkeypatch, first_day: int = 23) -> list[set[str]]:
    monkeypatch.setattr(rematch, "MAX_TENANTS_PER_RUN", cap)
    reached = []
    for day in range(runs):
        now = datetime(2026, 10, first_day + day, 6, 0, tzinfo=timezone.utc)
        rematch.run_rematch_once(feed_source=_Feed([]), now=now)
        reached.append(
            {
                tenant
                for tenant in ("tenant-a", "tenant-b", "tenant-c")
                if (rematch._get_operator_advisory_store().get_rematch_state(tenant) or {}).get("last_run", {}).get("status") == "complete"
                and rematch._get_operator_advisory_store().get_rematch_state(tenant)["last_run"]["at"] == now.isoformat()
            }
        )
    return reached


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_tenant_cap_rotates_so_every_tenant_is_reached_within_ceil_n_over_cap_runs(
    env: InMemoryOperatorAdvisoryStore, monkeypatch, tmp_path: Path, backend: str
) -> None:
    from agent_bom.api.operator_advisory_store import SQLiteOperatorAdvisoryStore
    from agent_bom.api.stores import _get_store

    if backend == "sqlite":
        set_operator_advisory_store(SQLiteOperatorAdvisoryStore(str(tmp_path / "advisories.db")))
    _get_store().put(_job("tenant-c", "php", "8.3.30"))
    reached = _reached_per_run(3, 1, monkeypatch)
    assert all(len(run) == 1 for run in reached)
    assert set().union(*reached) == {"tenant-a", "tenant-b", "tenant-c"}
    two_per_run = _reached_per_run(2, 2, monkeypatch, first_day=26)
    assert set().union(*two_per_run) == {"tenant-a", "tenant-b", "tenant-c"}
    skipped = rematch._get_operator_advisory_store().get_rematch_state(sorted({"tenant-a", "tenant-b", "tenant-c"} - two_per_run[-1])[0])
    assert skipped["last_run"]["reason"] == "tenant_cap"
