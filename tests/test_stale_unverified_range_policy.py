"""Stale local advisory rows the range receipt cannot verify are never confirmed findings.

Fixture: a SQLite advisory DB whose rows lost their range limits (``limit_version``
NULL — the v7→v8 upgrade-in-place path) plus a mocked live OSV answer.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agent_bom.db.lookup_fixes import LEGACY_RECEIPT_WARNING, UNVERIFIED_RANGE_WARNING
from agent_bom.db.schema import init_db
from agent_bom.db.sync import _ingest_osv_file
from agent_bom.models import Package
from agent_bom.scanners.scan_options import ScanOptions
from agent_bom.scanners.state import consume_coverage_warnings, consume_scan_warnings, reset_scan_warnings
from agent_bom.scanners.unverified_range_policy import UNVERIFIED_LOCAL_RANGE, withhold_unverified_fixes
from agent_bom.vuln_freshness import set_allow_stale_db

STALE_ID = "GHSA-q7rr-3cgh-j5r3"
PKG = ("npm", "@opentelemetry/sdk-node", "0.52.1")


def _osv_record(vuln_id: str, *, fixed: str, severity: str = "HIGH") -> dict:
    return {
        "id": vuln_id,
        "summary": f"advisory {vuln_id}",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": PKG[1]},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
        "database_specific": {"severity": severity},
    }


def _stale_db(path: Path) -> Path:
    conn = init_db(path)
    try:
        _ingest_osv_file(conn, json.dumps(_osv_record(STALE_ID, fixed="0.60.0")).encode(), "stale.json")
        conn.execute("UPDATE affected SET limit_version = NULL")
        conn.execute("INSERT INTO sync_meta(source,last_synced,record_count) VALUES ('osv','2026-08-01T00:00:00+00:00',1)")
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.fixture(autouse=True)
def _db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", _stale_db(tmp_path / "vulns.db"))
    monkeypatch.delenv("AGENT_BOM_ALLOW_STALE_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)
    reset_scan_warnings()
    set_allow_stale_db(False)
    yield
    set_allow_stale_db(False)
    reset_scan_warnings()


def _osv(monkeypatch: pytest.MonkeyPatch, answer: dict | None) -> list[int]:
    calls: list[int] = []

    async def _answer(packages):
        from agent_bom.scanners.state import _bump_scan_perf

        calls.append(len(packages))
        if answer is None:
            return {}
        _bump_scan_perf("osv_batches_answered", 1)
        return answer

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", _answer)
    return calls


def _scan(*, offline: bool = False) -> Package:
    from agent_bom.scanners.package_scan import scan_packages

    pkg = Package(name=PKG[1], version=PKG[2], ecosystem=PKG[0])
    asyncio.run(scan_packages([pkg], options=ScanOptions(offline=offline)))
    return pkg


def test_live_osv_answer_that_does_not_confirm_a_stale_row_drops_it_with_evidence(monkeypatch):
    calls = _osv(monkeypatch, {})  # OSV answered: the package is clean at this version

    pkg = _scan()

    assert calls, "the package with an unverified local row must be re-checked live"
    assert pkg.vulnerabilities == []
    assert pkg.possibly_affected == []
    notes = [w for w in consume_coverage_warnings() if w.get("kind") == "scan_note"]
    assert any(STALE_ID in json.dumps(note) and "live OSV" in json.dumps(note) for note in notes), notes


def test_live_osv_answer_that_confirms_the_advisory_wins_over_the_stale_row(monkeypatch):
    _osv(monkeypatch, {f"npm:{PKG[1]}@{PKG[2]}": [_osv_record(STALE_ID, fixed="0.57.0", severity="CRITICAL")]})

    pkg = _scan()

    assert [v.id for v in pkg.vulnerabilities] == [STALE_ID]
    (vuln,) = pkg.vulnerabilities
    assert vuln.match_confidence_tier != "unverified_range"
    assert vuln.fixed_version == "0.57.0"
    assert pkg.possibly_affected == []


def test_offline_unverified_row_is_a_labelled_candidate_not_a_finding(monkeypatch):
    _osv(monkeypatch, None)

    pkg = _scan(offline=True)

    assert pkg.vulnerabilities == []
    (entry,) = pkg.possibly_affected
    assert entry["id"] == STALE_ID
    assert entry["verdict"] == "possibly_affected"
    assert entry["reason"] == UNVERIFIED_LOCAL_RANGE
    assert entry["severity"] == "high"
    assert entry.get("fixed_version") is None and entry.get("upstream_fixed_version") is None
    assert "agent-bom db update" in entry["detail"]
    assert LEGACY_RECEIPT_WARNING in consume_scan_warnings()


def test_candidates_are_reported_but_never_gate_or_count(monkeypatch):
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
    from agent_bom.output.json_fmt import to_json
    from agent_bom.output.possibly_affected import possibly_affected_rows

    _osv(monkeypatch, None)
    pkg = _scan(offline=True)
    server = MCPServer(name="s", command="node", args=[], packages=[pkg])
    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/x", mcp_servers=[server])
    report = AIBOMReport(agents=[agent])

    assert report.to_findings() == []
    rows = possibly_affected_rows(report)
    assert [row["id"] for row in rows] == [STALE_ID]
    payload = to_json(report)
    assert payload["possibly_affected"][0]["reason"] == UNVERIFIED_LOCAL_RANGE
    assert payload["summary"]["total_vulnerabilities"] == 0


def test_stale_receipt_warning_is_informational_with_allow_stale_db():
    from agent_bom.evidence.scan_run import ScanOutcome, ScanRun, scanner_warning_issues
    from agent_bom.vuln_freshness import accepted_scan_warnings

    def issues(messages: list[str]):
        return scanner_warning_issues(messages, accepted=accepted_scan_warnings())

    strict = ScanRun(issues=issues([LEGACY_RECEIPT_WARNING, UNVERIFIED_RANGE_WARNING]))
    assert strict.outcome is ScanOutcome.PARTIAL
    assert all(issue.affects_coverage for issue in strict.issues)

    set_allow_stale_db(True)
    accepted = ScanRun(issues=issues([LEGACY_RECEIPT_WARNING, UNVERIFIED_RANGE_WARNING, "sparse local DB OSV fallback for 1 package(s)"]))
    assert accepted.outcome is ScanOutcome.PARTIAL  # an unrelated coverage warning still counts
    by_message = {issue.message: issue.affects_coverage for issue in accepted.issues}
    assert by_message[LEGACY_RECEIPT_WARNING] is False
    assert by_message[UNVERIFIED_RANGE_WARNING] is False
    assert by_message["sparse local DB OSV fallback for 1 package(s)"] is True
    only_stale = ScanRun(issues=issues([LEGACY_RECEIPT_WARNING]))
    assert only_stale.outcome is ScanOutcome.COMPLETE


def test_stale_receipt_warning_is_retired_when_live_osv_decided_every_row(monkeypatch):
    _osv(monkeypatch, {})

    _scan()

    assert LEGACY_RECEIPT_WARNING not in consume_scan_warnings()


def test_shared_policy_withholds_fixes_the_alias_merge_tried_to_borrow():
    from agent_bom.models import Severity, Vulnerability

    candidate = Vulnerability(
        id="CVE-2026-1", summary="x", severity=Severity.HIGH, match_confidence_tier="unverified_range", fixed_version="2.0"
    )
    confirmed = Vulnerability(id="CVE-2026-2", summary="y", severity=Severity.HIGH, fixed_version="3.0")
    withhold_unverified_fixes([candidate, confirmed])
    assert candidate.fixed_version is None
    assert confirmed.fixed_version == "3.0"


def test_check_and_scan_share_the_fix_withholding_policy(monkeypatch):
    """``check`` offline reports the same candidate with no fix, exactly as ``scan`` does."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    _osv(monkeypatch, None)
    result = CliRunner().invoke(main, ["check", f"{PKG[1]}@{PKG[2]}", "--ecosystem", "npm", "--format", "json", "--offline"])
    payload = json.loads(result.output)
    assert payload["vulnerability_count"] == 0
    assert payload["vulnerabilities"] == []
    (candidate,) = payload["possibly_affected"]
    assert candidate["id"] == STALE_ID and candidate.get("fixed_version") is None
    assert result.exit_code == 2, result.output  # outdated data OSV did not back stays incomplete


def test_withdrawn_osv_record_purges_the_row_it_ingested_earlier(tmp_path):
    """A re-sync retracts a withdrawn advisory instead of leaving its stale range active."""
    from agent_bom.db.lookup import lookup_package

    conn = init_db(tmp_path / "resync.db")
    try:
        record = _osv_record("GHSA-gv7w-rqvm-qjhr", fixed="0.60.0")
        _ingest_osv_file(conn, json.dumps(record).encode(), "live.json")
        assert lookup_package(conn, "npm", PKG[1], PKG[2])
        _ingest_osv_file(conn, json.dumps({**record, "withdrawn": "2026-06-17T00:00:00Z"}).encode(), "withdrawn.json")
        assert lookup_package(conn, "npm", PKG[1], PKG[2]) == []
        assert conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] == 0
    finally:
        conn.close()
