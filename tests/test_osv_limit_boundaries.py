"""OSV limits restrict a range without claiming that the limit is a fix."""

import json

import pytest

from agent_bom.db.lookup import lookup_package, lookup_packages_batch
from agent_bom.db.schema import init_db
from agent_bom.db.sync import _ingest_osv_file
from agent_bom.scanners.osv import parse_fixed_version
from agent_bom.scanners.package_scan import _is_version_affected


def advisory(events, *, versions=None, ecosystem="PyPI", name="boundary-example"):
    return {
        "id": "OSV-TEST-LIMIT",
        "summary": "Range boundary fixture",
        "affected": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
                "versions": versions or [],
            }
        ],
    }


@pytest.mark.parametrize(
    "events,version,expected",
    [
        ([{"introduced": "0"}, {"limit": "2.0"}], "1.9", True),
        ([{"introduced": "0"}, {"limit": "2.0"}], "2.0", False),
        ([{"introduced": "0"}, {"limit": "2.0"}], "3.0", False),
        ([{"introduced": "0"}, {"limit": "2.0"}, {"limit": "4.0"}], "3.0", True),
        ([{"introduced": "0"}, {"limit": "2.0"}, {"limit": "4.0"}], "4.0", False),
        ([{"introduced": "0"}, {"fixed": "4.0"}, {"limit": "2.0"}], "3.0", False),
        ([{"introduced": "0"}, {"limit": "2.0"}, {"limit": "*"}], "9.0", True),
    ],
)
@pytest.mark.parametrize("engine", ["online", "single", "batch"])
def test_limit_matching_agrees_online_and_offline(tmp_path, events, version, expected, engine):
    data = advisory(events)
    if engine == "online":
        assert _is_version_affected(data, "boundary-example", version, "pypi") is expected
        return
    # Use owning ingestion and both public database lookup paths.
    conn = init_db(tmp_path / "ranges.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        if engine == "single":
            assert bool(lookup_package(conn, "pypi", "boundary-example", version)) is expected
            return
        result = lookup_packages_batch(conn, [("pypi", "boundary-example", version)])
        assert bool(result.get(("pypi", "boundary-example", version))) is expected
    finally:
        conn.close()


def test_limit_is_not_a_fixed_version():
    assert parse_fixed_version(advisory([{"introduced": "0"}, {"limit": "2.0"}]), "boundary-example", "pypi", "1.0") is None


def test_listed_version_is_union_with_limited_range():
    assert _is_version_affected(advisory([{"introduced": "0"}, {"limit": "2.0"}], versions=["5.0"]), "boundary-example", "5.0", "pypi")


@pytest.mark.parametrize("limit", ["", None, "not-a-version", "1.*", "*garbage"])
def test_malformed_limit_is_not_an_unbounded_verified_match(tmp_path, limit):
    data = advisory([{"introduced": "0"}, {"limit": limit}])
    assert not _is_version_affected(data, "boundary-example", "1.0", "pypi")
    conn = init_db(tmp_path / "unknown.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        matches = lookup_package(conn, "pypi", "boundary-example", "1.0")
        assert len(matches) == 1
        assert matches[0].match_confidence_tier == "unverified_range"
    finally:
        conn.close()


def test_limited_range_does_not_cover_an_explicit_version_pin(tmp_path):
    data = advisory([{"introduced": "0"}, {"limit": "2.0"}], versions=["5.0"])
    conn = init_db(tmp_path / "pins.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        assert lookup_package(conn, "pypi", "boundary-example", "5.0")
        assert not lookup_package(conn, "pypi", "boundary-example", "4.0")
    finally:
        conn.close()


def test_populated_v7_upgrade_retains_candidates_until_source_refresh(tmp_path):
    from agent_bom.output.json_sections import _vulnerability_json
    from agent_bom.scanners.package_scan import _local_vuln_to_vulnerability
    from agent_bom.scanners.state import peek_scan_warnings, reset_scan_warnings_only

    path = tmp_path / "legacy.db"
    conn = init_db(path)
    conn.executescript("""
        DROP TABLE affected;
        CREATE TABLE affected (
            vuln_id TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
            ecosystem TEXT NOT NULL, package_name TEXT NOT NULL,
            introduced TEXT, fixed TEXT, last_affected TEXT,
            PRIMARY KEY (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
        );
        UPDATE schema_version SET version = 7;
        INSERT INTO vulns (id,summary,severity,source) VALUES ('legacy','old receipt','high','osv');
        INSERT INTO affected VALUES ('legacy','pypi','boundary-example','0','2.0','');
        INSERT INTO sync_meta (source,last_synced,record_count) VALUES ('osv','2026-10-01T00:00:00Z',1);
    """)
    conn.close()
    reset_scan_warnings_only()
    conn = init_db(path)
    try:
        row = conn.execute("SELECT * FROM affected").fetchone()
        assert row["vuln_id"] == "legacy" and row["fixed"] == "2.0"
        assert row["limit_version"] is None  # absent metadata is not infinity
        assert conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] == 1
        assert not conn.execute("SELECT * FROM sync_meta WHERE source='osv'").fetchall()
        matches = lookup_package(conn, "pypi", "boundary-example", "1.0")
        assert len(matches) == 1 and matches[0].match_confidence_tier == "unverified_range"
        exported = _vulnerability_json(_local_vuln_to_vulnerability(matches[0]))
        assert exported["match_confidence_tier"] == "unverified_range"
        assert exported["fixed_version"] is None
        assert any("unverified_range" in warning for warning in peek_scan_warnings())
        fresh = advisory([{"introduced": "0"}, {"limit": "0.5"}])
        fresh["id"] = "legacy"
        _ingest_osv_file(conn, json.dumps(fresh).encode(), "refreshed.json")
        assert not lookup_package(conn, "pypi", "boundary-example", "1.0")
        assert conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] == 1
    finally:
        conn.close()
        reset_scan_warnings_only()


@pytest.mark.parametrize("engine", ["online", "single", "batch"])
def test_unsorted_range_events_do_not_fill_safe_gaps(tmp_path, engine):
    data = advisory([{"fixed": "2.0"}, {"introduced": "0"}, {"fixed": "4.0"}, {"introduced": "3.0"}])
    conn = init_db(tmp_path / "unordered.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        for version, expected in [("1.0", True), ("2.5", False), ("3.5", True), ("4.0", False)]:
            if engine == "online":
                actual = _is_version_affected(data, "boundary-example", version, "pypi")
            elif engine == "single":
                actual = bool(lookup_package(conn, "pypi", "boundary-example", version))
            else:
                query = ("pypi", "boundary-example", version)
                actual = bool(lookup_packages_batch(conn, [query])[query])
            assert actual is expected, (engine, version)
    finally:
        conn.close()


@pytest.mark.parametrize("engine", ["online", "single", "batch"])
def test_other_package_fix_does_not_fill_an_unfixed_range(tmp_path, engine):
    data = advisory([{"introduced": "0"}, {"limit": "2.0"}])
    data["affected"].extend(advisory([{"introduced": "0"}, {"fixed": "9.0"}], name="different-package")["affected"])
    if engine == "online":
        assert parse_fixed_version(data, "boundary-example", "pypi", "1.0") is None
        return
    conn = init_db(tmp_path / "fixes.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        matches = (
            lookup_package(conn, "pypi", "boundary-example", "1.0")
            if engine == "single"
            else lookup_packages_batch(conn, [("pypi", "boundary-example", "1.0")])[("pypi", "boundary-example", "1.0")]
        )
        assert len(matches) == 1
        assert matches[0].fixed_version is None
    finally:
        conn.close()


@pytest.mark.parametrize("engine", ["online", "single", "batch"])
@pytest.mark.parametrize("range_type", ["GIT", "UNRECOGNIZED"])
def test_non_release_range_cannot_assert_package_version_membership(tmp_path, engine, range_type):
    data = advisory([{"introduced": "0"}])
    data["affected"][0]["ranges"][0]["type"] = range_type
    if engine == "online":
        assert not _is_version_affected(data, "boundary-example", "1.0", "pypi")
        return
    conn = init_db(tmp_path / "types.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        matches = (
            lookup_package(conn, "pypi", "boundary-example", "1.0")
            if engine == "single"
            else lookup_packages_batch(conn, [("pypi", "boundary-example", "1.0")])[("pypi", "boundary-example", "1.0")]
        )
        assert not matches
    finally:
        conn.close()


def test_read_only_legacy_bundle_preserves_unverified_candidates(tmp_path):
    import sqlite3

    from agent_bom.db.lookup import package_in_db, package_in_db_batch

    path = tmp_path / "readonly.db"
    conn = init_db(path)
    _ingest_osv_file(conn, json.dumps(advisory([{"introduced": "0"}, {"fixed": "2.0"}])).encode(), "fixture.json")
    conn.executescript("""
        ALTER TABLE affected RENAME TO affected_new;
        CREATE TABLE affected AS SELECT vuln_id,ecosystem,package_name,introduced,fixed,last_affected FROM affected_new;
        DROP TABLE affected_new;
        UPDATE schema_version SET version = 7;
    """)
    conn.close()
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        single = lookup_package(conn, "pypi", "boundary-example", "1.0")
        batch = lookup_packages_batch(conn, [("pypi", "boundary-example", "1.0")])[("pypi", "boundary-example", "1.0")]
        assert len(single) == len(batch) == 1
        assert all(item.match_confidence_tier == "unverified_range" and item.fixed_version is None for item in single + batch)
        assert not package_in_db(conn, "pypi", "boundary-example")
        assert not package_in_db_batch(conn, [("pypi", "boundary-example")])
        assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == 7
    finally:
        conn.close()


def test_unknown_range_is_not_suppressed_as_a_known_unfixed_distro_advisory():
    from agent_bom.models import Package, Severity, Vulnerability
    from agent_bom.scanners.package_scan import _suppress_unfixed_os_advisories

    package = Package(
        name="example",
        version="1.0",
        ecosystem="deb",
        vulnerabilities=[
            Vulnerability(id="CVE-2026-1111", summary="uncertain range", severity=Severity.HIGH, match_confidence_tier="unverified_range")
        ],
    )
    assert _suppress_unfixed_os_advisories([package]) == 0
    assert len(package.vulnerabilities) == 1


@pytest.mark.parametrize(
    "events",
    [
        [{"introduced": "0"}, {"last_affected": "1.9"}, {"introduced": "2.0"}, {"fixed": "2.2"}],
        [{"introduced": "0"}, {"fixed": "4.0"}, {"limit": "1.0"}],
    ],
)
def test_fix_requires_membership_in_the_same_complete_window(events):
    data = advisory(events, versions=["1.5"])
    assert parse_fixed_version(data, "boundary-example", "pypi", "1.5") is None
