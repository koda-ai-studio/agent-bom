"""An end-of-life Debian release scanned without local tracker data is not complete.

OSV publishes its per-CVE ``DEBIAN-CVE-*`` records only for supported Debian
releases; once a release ends, a live ``Debian:<n>`` query returns only DSA/DLA
advisories. Fixes that shipped without one are missed (nginx:1.21.6 on
Debian 11 matched 195 fixed CVEs live, far fewer than the Debian Security
Tracker lists). The scan must say so and name the command that loads the
tracker, never report a complete outcome.
"""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

from agent_bom.coverage import detect_release_coverage_gaps, is_scan_note
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.models import Package
from agent_bom.scanners.state import capture_coverage_warnings


def _debian(version: str, count: int = 6) -> list[Package]:
    return [Package(name=f"lib{i}", version="1.0-1", ecosystem="deb", distro_name="debian", distro_version=version) for i in range(count)]


def _db(rows: dict[str, int]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE affected (vuln_id TEXT, ecosystem TEXT, package_name TEXT, introduced TEXT, fixed TEXT, last_affected TEXT)")
    for ecosystem, count in rows.items():
        rows_for_release = [(f"CVE-{ecosystem}-{i}", ecosystem) for i in range(count)]
        conn.executemany("INSERT INTO affected VALUES (?, ?, 'p', '0', '1', NULL)", rows_for_release)
    return conn


def _live_gaps(packages: list[Package], conn: sqlite3.Connection | None = None) -> list[dict]:
    with capture_coverage_warnings():
        warnings = detect_release_coverage_gaps(packages, conn=conn)
    return [w for w in warnings if w.get("reason") == "release_live_feed_partial"]


def test_eol_debian_without_local_tracker_data_is_a_coverage_gap() -> None:
    [gap] = _live_gaps(_debian("11.3"))
    assert gap["release"] == "debian:11"
    assert not is_scan_note(gap)
    assert "agent-bom db update --source debian" in gap["detail"]
    assert gap["package_count"] == 6


def test_gap_marks_the_scan_partial() -> None:
    gaps = _live_gaps(_debian("11.3"))
    run = effective_scan_run(SimpleNamespace(coverage_warnings=gaps, scan_run=None))
    assert run.outcome is ScanOutcome.PARTIAL
    assert any(issue.affects_coverage and "db update" in issue.message for issue in run.issues)


def test_local_tracker_rows_for_the_release_close_the_gap() -> None:
    conn = _db({"debian:11": 500, "debian:12": 500})
    assert _live_gaps(_debian("11.3"), conn) == []


def test_local_db_without_that_release_keeps_the_gap() -> None:
    conn = _db({"debian:12": 500})
    assert [gap["release"] for gap in _live_gaps(_debian("11.3"), conn)] == ["debian:11"]


def test_supported_debian_release_has_no_live_feed_gap() -> None:
    assert _live_gaps(_debian("12.5")) == []


def test_osv_fallback_warning_counts_only_packages_the_local_db_would_have_answered(monkeypatch) -> None:
    from agent_bom.scanners import package_coverage, state

    monkeypatch.setattr(package_coverage, "local_db_untrusted", lambda **_kw: False)
    monkeypatch.setattr(package_coverage, "local_osv_is_scoped", lambda: False)
    monkeypatch.setattr(
        package_coverage, "_scanners_patchable", lambda name: (lambda ecos: set()) if name == "_db_covered_ecosystems" else None
    )
    packages = _debian("11.3")
    gaps = _live_gaps(packages)
    state.reset_scan_warnings()
    targets, _ = package_coverage._select_osv_targets(packages, False, [], set(), gaps)
    assert targets == packages
    assert not [w for w in state.peek_scan_warnings() if "fallback" in w]
    held = {package_coverage._package_db_key(packages[0])}
    package_coverage._select_osv_targets(packages, False, [], held, gaps)
    assert "sparse local DB OSV fallback for 1 package(s)" in state.peek_scan_warnings()
