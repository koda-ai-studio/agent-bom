"""A distro advisory takes its severity from the CVEs it links, looked up in bounded batches.

OSV publishes DSA/DLA rollups with no severity. A fresh install has no local
database, so the linked CVE records are fetched from the OSV host the scanner
already uses. Every gap stays ``unknown`` and is reported; a score is never
invented, and the Debian tracker's fixed or not-affected verdict is respected.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.scanners import linked_cve_lookup, upstream_severity
from agent_bom.scanners.linked_cve_lookup import LinkedCveQuery, lookup_linked_cves
from agent_bom.scanners.state import peek_coverage_warnings, peek_scan_warnings, reset_scan_warnings
from agent_bom.scanners.upstream_severity import resolve_distro_advisory_severity
from agent_bom.storage import state_home

CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
MEDIUM = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"


def _record(vid: str, vector: str | None = None, affected: list[tuple[str, str, str]] | None = None) -> dict:
    record: dict = {"id": vid}
    if vector:
        record["severity"] = [{"type": "CVSS_V3", "score": vector}]
    record["affected"] = [
        {
            "package": {"name": name, "ecosystem": ecosystem},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, *([{"fixed": fixed}] if fixed else [])]}],
        }
        for name, ecosystem, fixed in affected or []
    ]
    return record


class FakeOsv:
    """Stands in for ``request_with_retry``; answers from a dict and records every request."""

    def __init__(self, records: dict[str, dict] | None = None, status: int = 200) -> None:
        self.records = records or {}
        self.status = status
        self.requested: list[str] = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def __call__(self, _client, method: str, url: str, **_kwargs):
        assert method == "GET"
        assert url.startswith("https://api.osv.dev/v1/vulns/"), url
        vid = url.rsplit("/", 1)[-1]
        self.requested.append(vid)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        await asyncio.sleep(0)
        self.in_flight -= 1
        if self.status != 200:
            return httpx.Response(self.status)
        if vid in self.records:
            return httpx.Response(200, json=self.records[vid])
        return httpx.Response(404)


class FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(state_home, "state_dir", lambda: tmp_path)
    monkeypatch.setattr(linked_cve_lookup, "create_client", lambda **_kwargs: FakeClient())
    monkeypatch.setattr(upstream_severity.db_schema, "DB_PATH", tmp_path / "absent.db")
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def _pkg(*vulns: Vulnerability, name: str = "libpam0g", version: str = "1.4.0-9+deb11u1", release: str = "11") -> Package:
    return Package(
        name=name,
        version=version,
        ecosystem="deb",
        distro_name="debian",
        distro_version=release,
        source_package="pam",
        vulnerabilities=list(vulns),
    )


def _dsa(vid: str = "DSA-1-1", *cves: str) -> Vulnerability:
    upstream = [*cves, *(f"DEBIAN-{cve}" for cve in cves)]
    return Vulnerability(id=vid, summary="", severity=Severity.UNKNOWN, upstream_ids=upstream, advisory_sources=["osv"])


def _resolve(packages: list[Package], osv: FakeOsv, *, offline: bool = False) -> int:
    return asyncio.run(resolve_distro_advisory_severity(packages, offline=offline, request_fn=osv))


def test_rollup_takes_its_strongest_linked_cve_and_names_it() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001", "CVE-2024-0002")
    osv = FakeOsv(
        {"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM), "DEBIAN-CVE-2024-0002": _record("DEBIAN-CVE-2024-0002", CRITICAL)}
    )

    assert _resolve([_pkg(vuln)], osv) == 1

    assert vuln.severity == Severity.CRITICAL
    assert vuln.cvss_score == 9.8
    assert vuln.cvss_vector == CRITICAL
    assert vuln.severity_source == "upstream_cve:CVE-2024-0002"
    assert vuln.severity_note is None
    assert not peek_scan_warnings()


def test_shared_cves_are_requested_once_however_many_findings_link_them() -> None:
    packages = [_pkg(_dsa(f"DSA-{index}-1", "CVE-2024-0001", "CVE-2024-0002"), name=f"lib{index}", version="1.0-1") for index in range(40)]
    records = {f"DEBIAN-{cve}": _record(f"DEBIAN-{cve}", MEDIUM) for cve in ("CVE-2024-0001", "CVE-2024-0002")}
    osv = FakeOsv(records)

    _resolve(packages, osv)

    assert sorted(osv.requested) == ["DEBIAN-CVE-2024-0001", "DEBIAN-CVE-2024-0002"]
    assert all(vuln.severity == Severity.MEDIUM for pkg in packages for vuln in pkg.vulnerabilities)


def test_concurrency_stays_inside_the_limit() -> None:
    cves = [f"CVE-2024-{index:05d}" for index in range(linked_cve_lookup.CONCURRENCY * 4)]
    osv = FakeOsv({f"DEBIAN-{cve}": _record(f"DEBIAN-{cve}", MEDIUM) for cve in cves})

    _resolve([_pkg(_dsa("DSA-1-1", *cves))], osv)

    assert len(osv.requested) == len(cves)
    assert 1 < osv.max_in_flight <= linked_cve_lookup.CONCURRENCY


def test_cve_record_is_the_fallback_when_the_debian_record_has_no_score() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001"), "CVE-2024-0001": _record("CVE-2024-0001", CRITICAL)})

    _resolve([_pkg(vuln)], osv)

    assert osv.requested == ["DEBIAN-CVE-2024-0001", "CVE-2024-0001"]
    assert vuln.severity == Severity.CRITICAL


def test_non_debian_advisory_uses_the_cve_record() -> None:
    vuln = Vulnerability(id="ALSA-2024:1", summary="", severity=Severity.UNKNOWN, upstream_ids=["CVE-2024-0001"])
    pkg = Package(name="openssl", version="1.0", ecosystem="rpm", vulnerabilities=[vuln])
    osv = FakeOsv({"CVE-2024-0001": _record("CVE-2024-0001", MEDIUM)})

    _resolve([pkg], osv)

    assert osv.requested == ["CVE-2024-0001"]
    assert vuln.severity_source == "upstream_cve:CVE-2024-0001"


def test_language_ecosystem_advisory_makes_no_lookup() -> None:
    vuln = Vulnerability(id="GHSA-aaaa-bbbb-cccc", summary="", severity=Severity.UNKNOWN, upstream_ids=["CVE-2024-0001"])
    osv = FakeOsv()

    _resolve([Package(name="requests", version="1.0", ecosystem="pypi", vulnerabilities=[vuln])], osv)

    assert osv.requested == []


def test_hostile_upstream_id_is_never_placed_in_a_request() -> None:
    vuln = Vulnerability(
        id="DSA-1-1",
        summary="",
        severity=Severity.UNKNOWN,
        upstream_ids=["CVE-2024-0001", "DEBIAN-..", "CVE-2024-0001:evil", "EVIL-CVE-2024-0001x"],
    )
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM)})

    _resolve([_pkg(vuln)], osv)

    assert osv.requested == ["DEBIAN-CVE-2024-0001"]


def test_offline_makes_no_request_keeps_unknown_and_says_so() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL)})

    _resolve([_pkg(vuln)], osv, offline=True)

    assert osv.requested == []
    assert vuln.severity == Severity.UNKNOWN
    assert vuln.severity_source is None
    warnings = peek_scan_warnings()
    assert any("1 distro advisories" in text and "offline" in text for text in warnings)


@pytest.mark.parametrize("status", [429, 503])
def test_failed_lookup_keeps_unknown_stops_early_and_is_not_cached(status: int) -> None:
    cves = [f"CVE-2024-{index:05d}" for index in range(linked_cve_lookup.BATCH_SIZE * 3)]
    vuln = _dsa("DSA-1-1", *cves)
    failing = FakeOsv(status=status)

    _resolve([_pkg(vuln)], failing)

    assert len(failing.requested) == linked_cve_lookup.BATCH_SIZE, "a failing batch stops the rest"
    assert vuln.severity == Severity.UNKNOWN
    assert any("distro advisories" in text and ("rate limit" in text or "failed" in text) for text in peek_scan_warnings())

    healthy = FakeOsv({f"DEBIAN-{cve}": _record(f"DEBIAN-{cve}", MEDIUM) for cve in cves})
    _resolve([_pkg(vuln)], healthy)
    assert len(healthy.requested) == len(cves), "no failure was cached as an answer"
    assert vuln.severity == Severity.MEDIUM


def test_partly_answered_rollup_is_marked_as_a_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(linked_cve_lookup, "MAX_LOOKUPS", 1)
    vuln = _dsa("DSA-1-1", "CVE-2024-0001", "CVE-2024-0002")
    osv = FakeOsv({f"DEBIAN-{cve}": _record(f"DEBIAN-{cve}", MEDIUM) for cve in ("CVE-2024-0001", "CVE-2024-0002")})

    _resolve([_pkg(vuln)], osv)

    assert len(osv.requested) == 1
    assert vuln.severity == Severity.MEDIUM
    assert vuln.severity_note is not None and "1 of 2" in vuln.severity_note
    assert any("understated" in text for text in peek_scan_warnings())


def test_budget_reaches_every_advisory_before_a_second_cve_of_any(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(linked_cve_lookup, "MAX_LOOKUPS", 2)
    big = _dsa("DSA-1-1", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")
    small = _dsa("DSA-2-1", "CVE-2024-0009")
    osv = FakeOsv({f"DEBIAN-CVE-2024-000{n}": _record(f"DEBIAN-CVE-2024-000{n}", MEDIUM) for n in (1, 2, 3, 9)})

    _resolve([_pkg(big, small)], osv)

    assert sorted(osv.requested) == ["DEBIAN-CVE-2024-0001", "DEBIAN-CVE-2024-0009"]
    assert small.severity == Severity.MEDIUM
    assert big.severity == Severity.MEDIUM


def test_deadline_keeps_what_was_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(linked_cve_lookup, "DEADLINE_SECONDS", 0.0)
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")

    _resolve([_pkg(vuln)], FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM)}))

    assert vuln.severity == Severity.UNKNOWN
    assert any("budget" in text for text in peek_scan_warnings())


def test_cve_with_no_rating_anywhere_stays_unknown_and_warns() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001")})

    _resolve([_pkg(vuln)], osv)

    assert vuln.severity == Severity.UNKNOWN
    assert vuln.cvss_score is None
    assert any("Severity is missing for 1 distro advisories" in text for text in peek_scan_warnings())


def test_second_scan_is_served_from_the_cache() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    first = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:12", "1.5")])})
    _resolve([_pkg(vuln)], first)
    assert first.requested

    again = _dsa("DSA-1-1", "CVE-2024-0001")
    second = FakeOsv()
    _resolve([_pkg(again)], second)

    assert second.requested == []
    assert again.severity == Severity.CRITICAL
    assert again.severity_source == "upstream_cve:CVE-2024-0001"


def test_cached_answers_serve_an_offline_scan(tmp_path: Path) -> None:
    _resolve([_pkg(_dsa("DSA-1-1", "CVE-2024-0001"))], FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL)}))
    reset_scan_warnings()

    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv()
    _resolve([_pkg(vuln)], osv, offline=True)

    assert osv.requested == []
    assert vuln.severity == Severity.CRITICAL
    assert not peek_scan_warnings()


def test_expired_cache_entries_are_fetched_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve([_pkg(_dsa("DSA-1-1", "CVE-2024-0001"))], FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL)}))
    future = time.time() + linked_cve_lookup.RATED_TTL_SECONDS + 60
    monkeypatch.setattr(linked_cve_lookup.time, "time", lambda: future)

    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM)})
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    _resolve([_pkg(vuln)], osv)

    assert osv.requested == ["DEBIAN-CVE-2024-0001"]
    assert vuln.severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        json.dumps({"version": 1, "entries": []}),
        json.dumps({"version": 1, "entries": {"DEBIAN-CVE-2024-0001": {"fetched_at": "soon", "cvss_score": "high"}}}),
        json.dumps({"version": 1, "entries": {"DEBIAN-CVE-2024-0001": {"fetched_at": 9e12, "label": 7, "tracker": "x"}}}),
    ],
)
def test_malformed_cache_is_ignored_not_trusted(tmp_path: Path, content: str) -> None:
    (tmp_path / linked_cve_lookup.CACHE_FILENAME).write_text(content)
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM)})

    _resolve([_pkg(vuln)], osv)

    assert osv.requested == ["DEBIAN-CVE-2024-0001"]
    assert vuln.severity == Severity.MEDIUM


def test_unwritable_cache_does_not_fail_the_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state_home, "state_dir", lambda: tmp_path / "missing" / "dir")
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    (tmp_path / "missing").write_text("a file, so the directory cannot be created")

    _resolve([_pkg(vuln)], FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM)}))

    assert vuln.severity == Severity.MEDIUM


def test_lookup_reports_requests_and_cache_hits() -> None:
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM)})
    query = LinkedCveQuery("CVE-2024-0001", "DEBIAN-CVE-2024-0001")

    first = asyncio.run(lookup_linked_cves([query], offline=False, request_fn=osv))
    second = asyncio.run(lookup_linked_cves([query], offline=False, request_fn=osv))

    assert (first.requests, first.cache_hits, first.gap_reason) == (1, 0, None)
    assert (second.requests, second.cache_hits, second.gap_reason) == (0, 1, None)


# ── The Debian tracker's verdict outranks a linked score ──


def test_tracker_fixed_in_the_installed_version_excludes_that_cve() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001", "CVE-2024-0002")
    records = {
        "DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:12", "1.5.2-6")]),
        "DEBIAN-CVE-2024-0002": _record("DEBIAN-CVE-2024-0002", MEDIUM, [("pam", "Debian:12", "1.7.0-1")]),
    }

    _resolve([_pkg(vuln, version="1.5.2-6", release="12")], FakeOsv(records))

    assert vuln.severity == Severity.MEDIUM
    assert vuln.severity_source == "upstream_cve:CVE-2024-0002"
    assert vuln.severity_note is not None and "CVE-2024-0001" in vuln.severity_note


def test_tracker_open_or_later_fix_keeps_the_cve() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001", "CVE-2024-0002")
    records = {
        "DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:12", "")]),
        "DEBIAN-CVE-2024-0002": _record("DEBIAN-CVE-2024-0002", MEDIUM, [("pam", "Debian:12", "1.7.0-1")]),
    }

    _resolve([_pkg(vuln, version="1.5.2-6", release="12")], FakeOsv(records))

    assert vuln.severity == Severity.CRITICAL
    assert vuln.severity_note is None


def test_release_the_tracker_omits_while_supported_means_not_affected() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001", "CVE-2024-0002")
    records = {
        "DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:13", "1.7.0-1")]),
        "DEBIAN-CVE-2024-0002": _record("DEBIAN-CVE-2024-0002", MEDIUM, [("pam", "Debian:12", "1.7.0-1")]),
    }

    _resolve([_pkg(vuln, version="1.5.2-6", release="12")], FakeOsv(records))

    assert vuln.severity == Severity.MEDIUM


def test_all_linked_cves_excluded_stays_unknown_with_a_reason_not_a_coverage_gap() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    records = {"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:12", "1.5.2-6")])}

    _resolve([_pkg(vuln, version="1.5.2-6", release="12")], FakeOsv(records))

    assert vuln.severity == Severity.UNKNOWN
    assert vuln.cvss_score is None
    assert vuln.severity_source is None
    assert vuln.severity_note is not None and "tracker" in vuln.severity_note
    assert not peek_scan_warnings()


def test_end_of_life_release_has_no_tracker_verdict_so_the_linked_score_stands() -> None:
    """Debian 11 left the tracker feed at end of life: omission there says nothing about the package."""
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    records = {"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:12", "1.5.2-6")])}

    _resolve([_pkg(vuln, version="1.4.0-9+deb11u1", release="11")], FakeOsv(records))

    assert vuln.severity == Severity.CRITICAL
    assert vuln.severity_source == "upstream_cve:CVE-2024-0001"


def test_end_of_life_release_still_listed_for_another_cve_is_treated_as_tracked() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001", "CVE-2024-0002")
    records = {
        "DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:12", "1.5.2-6")]),
        "DEBIAN-CVE-2024-0002": _record("DEBIAN-CVE-2024-0002", MEDIUM, [("pam", "Debian:11", "1.4.0-9+deb11u2")]),
    }

    _resolve([_pkg(vuln, version="1.4.0-9+deb11u1", release="11")], FakeOsv(records))

    assert vuln.severity == Severity.MEDIUM


def test_cve_record_alone_gives_no_tracker_verdict() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv({"CVE-2024-0001": _record("CVE-2024-0001", CRITICAL)})

    _resolve([_pkg(vuln, release="12")], osv)

    assert vuln.severity == Severity.CRITICAL


def test_package_without_release_metadata_gets_no_tracker_verdict() -> None:
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    pkg = Package(name="libpam0g", version="1.5.2-6", ecosystem="deb", vulnerabilities=[vuln])
    records = {"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL, [("pam", "Debian:12", "1.5.2-6")])}

    _resolve([pkg], FakeOsv(records))

    assert vuln.severity == Severity.CRITICAL


def test_local_tracker_row_fixing_the_installed_version_excludes_the_cve(tmp_path: Path) -> None:
    import sqlite3

    db = tmp_path / "local.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE vulns (id TEXT PRIMARY KEY, severity TEXT, cvss_score REAL, cvss_vector TEXT);"
        "CREATE TABLE epss_scores (cve_id TEXT, probability REAL, percentile REAL);"
        "CREATE TABLE kev_entries (cve_id TEXT, date_added TEXT, due_date TEXT);"
        "CREATE TABLE affected (vuln_id TEXT, ecosystem TEXT, package_name TEXT, fixed TEXT);"
    )
    conn.execute("INSERT INTO vulns VALUES ('CVE-2024-0001', 'critical', 9.8, ?)", (CRITICAL,))
    conn.execute("INSERT INTO affected VALUES ('DEBIAN-CVE-2024-0001', 'debian:11', 'pam', '1.4.0-9+deb11u1')")
    conn.commit()
    conn.close()
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")

    asyncio.run(resolve_distro_advisory_severity([_pkg(vuln, release="11")], offline=True, db_path=db, request_fn=FakeOsv()))

    assert vuln.severity == Severity.UNKNOWN
    assert vuln.severity_note is not None and "tracker" in vuln.severity_note


def test_cve_filed_under_another_source_package_is_no_verdict_on_this_one() -> None:
    """DSA-5990-1 fixes libxml2 for CVE-2025-7425, which the tracker files under libxslt."""
    vuln = _dsa("DSA-5990-1", "CVE-2025-7425")
    pkg = _pkg(vuln, name="libxml2", version="2.9.14+dfsg-1.3~deb12u1", release="12")
    pkg.source_package = "libxml2"
    records = {"DEBIAN-CVE-2025-7425": _record("DEBIAN-CVE-2025-7425", CRITICAL, [("libxslt", "Debian:12", "1.1.35-1+deb12u2")])}

    _resolve([pkg], FakeOsv(records))

    assert vuln.severity == Severity.CRITICAL
    assert vuln.severity_source == "upstream_cve:CVE-2025-7425"
    assert vuln.severity_note is None


def test_namespace_default_on_a_record_is_not_a_rating_to_inherit() -> None:
    defaulted = Vulnerability(
        id="DEBIAN-CVE-2024-0001",
        aliases=["CVE-2024-0001"],
        summary="",
        severity=Severity.MEDIUM,
        severity_source="distro_advisory_heuristic",
    )
    rollup = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL)})

    _resolve([_pkg(defaulted, rollup, release="12")], osv)

    assert osv.requested == ["DEBIAN-CVE-2024-0001"]
    assert rollup.severity == Severity.CRITICAL


def test_namespace_default_on_a_distro_cve_takes_the_linked_score() -> None:
    vuln = Vulnerability(id="CVE-2024-0001", summary="", severity=Severity.MEDIUM, severity_source="distro_advisory_heuristic")
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001"), "CVE-2024-0001": _record("CVE-2024-0001", CRITICAL)})

    _resolve([_pkg(vuln, release="12")], osv)

    assert vuln.severity == Severity.CRITICAL
    assert vuln.severity_source == "upstream_cve:CVE-2024-0001"


def test_namespace_default_with_no_linked_score_stays_labelled_as_a_default() -> None:
    vuln = Vulnerability(id="CVE-2024-0001", summary="", severity=Severity.MEDIUM, severity_source="distro_advisory_heuristic")

    _resolve([_pkg(vuln, release="12")], FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001")}))

    assert vuln.severity == Severity.MEDIUM
    assert vuln.severity_source == "distro_advisory_heuristic"
    assert vuln.severity_note is None
    assert not peek_scan_warnings()


def test_language_ecosystem_default_makes_no_lookup() -> None:
    vuln = Vulnerability(
        id="GHSA-aaaa-bbbb-cccc", summary="", severity=Severity.MEDIUM, severity_source="ghsa_heuristic", upstream_ids=["CVE-2024-0001"]
    )
    osv = FakeOsv()

    _resolve([Package(name="requests", version="1.0", ecosystem="pypi", vulnerabilities=[vuln])], osv)

    assert osv.requested == []
    assert vuln.severity_source == "ghsa_heuristic"


def test_offline_environment_flag_stops_the_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_VULN_DB_OFFLINE", "1")
    vuln = _dsa("DSA-1-1", "CVE-2024-0001")
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", CRITICAL)})

    _resolve([_pkg(vuln)], osv)

    assert osv.requested == []
    assert vuln.severity == Severity.UNKNOWN
    assert any("offline" in text for text in peek_scan_warnings())


# ── Findings with nothing to link ──


def test_unknown_primary_cve_on_a_distro_package_resolves_from_itself() -> None:
    vuln = Vulnerability(id="CVE-2024-0001", summary="", severity=Severity.UNKNOWN)
    osv = FakeOsv({"DEBIAN-CVE-2024-0001": _record("DEBIAN-CVE-2024-0001", MEDIUM)})

    _resolve([_pkg(vuln, release="11")], osv)

    assert osv.requested == ["DEBIAN-CVE-2024-0001"]
    assert vuln.severity == Severity.MEDIUM


def test_advisory_without_any_cve_stays_unknown_and_is_a_note_not_a_gap() -> None:
    vuln = Vulnerability(id="DLA-3972-1", summary="tzdata update", severity=Severity.UNKNOWN)
    osv = FakeOsv()

    _resolve([_pkg(vuln, name="tzdata", release="11")], osv)

    assert osv.requested == []
    assert vuln.severity == Severity.UNKNOWN
    assert vuln.severity_note is not None and "links no CVE" in vuln.severity_note
    assert not peek_scan_warnings()
    notes = [item for item in peek_coverage_warnings() if item.get("reason") == "distro_advisory_without_cve"]
    assert len(notes) == 1 and "1 distro advisories" in notes[0]["detail"]


def test_scan_packages_resolves_a_fresh_install_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.scanners import package_scan
    from agent_bom.scanners.scan_options import ScanOptions

    vuln = _dsa("DSA-5218-1", "CVE-2022-37434")
    pkg = _pkg(vuln, name="zlib1g", version="1:1.2.11.dfsg-2+deb11u1", release="11")
    calls: list[dict] = []

    async def fake_resolve(packages, *, offline, **_kwargs):
        calls.append({"offline": offline, "packages": list(packages)})
        return 0

    monkeypatch.setattr(package_scan, "resolve_distro_advisory_severity", fake_resolve)
    monkeypatch.setattr(package_scan, "_query_osv_results", _no_osv_results)

    asyncio.run(package_scan.scan_packages([pkg], options=ScanOptions(offline=False)))

    assert len(calls) == 1
    assert calls[0]["offline"] is False
    assert any(item.name == "zlib1g" for item in calls[0]["packages"])


async def _no_osv_results(*_args, **_kwargs):
    return {}
