"""A feed advisory is the union of its alias records, never a single row.

OSV stores CVE-2023-43804 twice over: the CVE row carries only distribution
ranges (Alpine ``py3-urllib3``), while the PyPI range lives on its GHSA alias
row, whose id keeps a lowercase body. A lookup that took one row reported a
PyPI urllib3 1.26.4 asset as clean although the scan itself flags it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.db.schema import init_db, open_existing_db_readonly
from agent_bom.scanners.advisory_affected import affected_answer, feed_advisory_from_db

_CVE = "CVE-2023-43804"
_GHSA = "GHSA-v845-jxx5-vc9f"


def _vuln(conn, vuln_id: str, aliases: str, source: str = "osv", severity: str = "unknown") -> None:
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, aliases, published, source) VALUES (?, ?, ?, ?, ?, ?)",
        (vuln_id, "Cookie header leaks on cross-origin redirect", severity, aliases, "2023-10-02T00:00:00Z", source),
    )


def _range(conn, vuln_id: str, ecosystem: str, name: str, fixed: str) -> None:
    conn.execute(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected) VALUES (?, ?, ?, '0', ?, '')",
        (vuln_id, ecosystem, name, fixed),
    )


@pytest.fixture()
def alias_db(tmp_path: Path) -> Path:
    path = tmp_path / "vulns.db"
    conn = init_db(path)
    _vuln(conn, _CVE, "", severity="medium")
    _range(conn, _CVE, "alpine:v3.18", "py3-urllib3", "1.26.17-r0")
    _vuln(conn, _GHSA, _CVE, source="ghsa", severity="high")
    _range(conn, _GHSA, "pypi", "urllib3", "1.26.17")
    _range(conn, _GHSA, "pypi", "urllib3", "2.0.6")
    _vuln(conn, "PYSEC-2023-192", f"{_CVE},{_GHSA}")
    _vuln(conn, "CVE-2022-34265", "")
    _vuln(conn, "GHSA-p64x-8rxx-wf6q", "CVE-2022-34265", source="ghsa", severity="critical")
    _range(conn, "GHSA-p64x-8rxx-wf6q", "pypi", "django", "3.2.14")
    conn.commit()
    conn.close()
    return path


def _report() -> dict:
    packages = [
        {"name": "urllib3", "version": "1.26.4", "ecosystem": "pypi"},
        {"name": "django", "version": "3.2.0", "ecosystem": "pypi"},
    ]
    return {
        "ai_bom_version": "1",
        "scan_id": "scan-py",
        "scan_completed_at": "2026-10-25T00:00:00+00:00",
        "agents": [{"name": "project", "mcp_servers": [{"name": "requirements.txt", "packages": packages}]}],
    }


def _lookup(db: Path, advisory_id: str):
    conn = open_existing_db_readonly(db)
    try:
        return feed_advisory_from_db(conn, advisory_id)
    finally:
        conn.close()


@pytest.mark.parametrize("requested", [_CVE, _CVE.lower(), _GHSA, _GHSA.upper(), "PYSEC-2023-192"])
def test_feed_advisory_unions_every_alias_record(alias_db: Path, requested: str) -> None:
    advisory = _lookup(alias_db, requested)
    assert advisory is not None
    products = {(p.ecosystem, p.name) for p in advisory.affected}
    assert products == {("alpine:v3.18", "py3-urllib3"), ("pypi", "urllib3")}
    answer = affected_answer(advisory, [_report()], source="feed")
    assert answer["summary"]["affected"] == 1
    assert answer["summary"]["clean_scanned"] == 0
    row = answer["rows"][0]
    assert (row["package"]["name"], row["installed_version"], row["fixed_version"], row["verdict"]) == (
        "urllib3",
        "1.26.4",
        "1.26.17",
        "affected",
    )
    assert {advisory.id, *advisory.aliases} >= {_CVE, _GHSA}
    assert advisory.severity == "high"


def test_cve_row_without_ranges_resolves_through_its_ghsa_alias(alias_db: Path) -> None:
    advisory = _lookup(alias_db, "CVE-2022-34265")
    assert advisory is not None and advisory.id == "CVE-2022-34265"
    assert advisory.severity == "critical"
    answer = affected_answer(advisory, [_report()], source="feed")
    assert [(r["package"]["name"], r["fixed_version"], r["verdict"]) for r in answer["rows"]] == [("django", "3.2.14", "affected")]


def test_every_id_the_matcher_reports_answers_affected_for_that_package(alias_db: Path) -> None:
    """The scan and the advisory answer read one DB; the answer never clears what the scan flags."""
    from agent_bom.db.lookup import lookup_package

    conn = open_existing_db_readonly(alias_db)
    try:
        flagged = {
            (package["name"], vuln.id, alias)
            for package in _report()["agents"][0]["mcp_servers"][0]["packages"]
            for vuln in lookup_package(conn, "PyPI", package["name"], package["version"])
            for alias in [vuln.id, *getattr(vuln, "aliases", [])]
        }
        assert {(name, vuln_id) for name, vuln_id, _ in flagged} >= {("urllib3", _GHSA), ("django", "GHSA-p64x-8rxx-wf6q")}
        for name, _vuln_id, requested in sorted(flagged):
            advisory = feed_advisory_from_db(conn, requested)
            assert advisory is not None, requested
            verdicts = {r["package"]["name"]: r["verdict"] for r in affected_answer(advisory, [_report()], source="feed")["rows"]}
            assert verdicts.get(name) == "affected", (requested, verdicts)
    finally:
        conn.close()
