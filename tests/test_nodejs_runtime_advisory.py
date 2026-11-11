"""Node.js runtimes are assessed against the Node.js security working group core index."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from agent_bom.coverage import RUNTIME_COVERAGE_UNKNOWN
from agent_bom.models import Package, Severity
from agent_bom.scanners import nodejs_advisory_data as data
from agent_bom.scanners import scan_packages
from agent_bom.scanners.nodejs_advisory import is_nodejs_runtime, matching_findings, scan_nodejs_runtimes
from agent_bom.scanners.runtime_coverage import detect_runtime_coverage_gaps
from agent_bom.scanners.state import peek_coverage_warnings, reset_scan_warnings

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

INDEX = {
    # one CVE across three supported lines, fixed on each
    "201": {
        "cve": ["CVE-2026-106072"],
        "vulnerable": "22.x || 24.x || 26.x",
        "patched": "^22.23.4 || ^24.22.1 || ^26.12.1",
        "ref": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
        "description": "Improper certificate validation for non-canonical IPv4 hostnames",
        "overview": "A flaw in TLS hostname verification.",
        "affectedEnvironments": ["all"],
        "severity": "medium",
    },
    # an older line with no patched release listed for 20.x
    "150": {
        "cve": ["CVE-2025-0001", "CVE-2025-0002"],
        "vulnerable": "18.x || 20.x || 22.x",
        "patched": "^18.20.9 || ^22.12.0",
        "overview": "Two CVEs fixed by one release.\n\nMore detail.",
        "affectedEnvironments": ["all"],
        "severity": "high",
    },
    # Windows-only: not applicable to a POSIX runtime
    "154": {
        "cve": ["CVE-2025-27210"],
        "vulnerable": "20.x || 22.x || 24.x",
        "patched": "^20.19.4 || ^22.17.1 || ^24.4.1",
        "affectedEnvironments": ["win32"],
        "severity": "high",
    },
    # no CVE assigned; the working group identifier stands in
    "9": {"cve": [], "vulnerable": "18.x", "patched": "^18.20.5", "affectedEnvironments": ["all"], "severity": "unknown"},
    # fixed by the upper bound of the vulnerable range itself
    "24": {
        "cve": ["CVE-2016-1669"],
        "vulnerable": ">=18.0.0 <18.2.0",
        "patched": "^4.4.6",
        "affectedEnvironments": ["linux"],
        "severity": "critical",
    },
}


SCHEDULE = {
    "v0.10": {"start": "2013-03-11", "end": "2016-10-31"},
    "v18": {"start": "2022-04-19", "end": "2025-04-30", "codename": "Hydrogen"},
    "v20": {"start": "2023-04-18", "end": "2026-04-30", "codename": "Iron"},
    "v22": {"start": "2024-04-24", "end": "2027-04-30", "codename": "Jod"},
    "v24": {"start": "2025-05-06", "end": "2028-04-30", "codename": "Krypton"},
    "v26": {"start": "2026-05-05", "end": "2029-04-30", "codename": "Lithium"},
}


def _snapshot(path: Path, *, fetched_at: datetime = NOW, entries: dict | None = None) -> Path:
    payload = data.snapshot_payload(json.dumps(entries or INDEX).encode(), json.dumps(SCHEDULE).encode(), fetched_at=fetched_at)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _node(version: str = "18.1.0") -> Package:
    return Package(
        name="node",
        version=version,
        ecosystem="generic",
        purl=f"pkg:generic/nodejs/node@{version}",
        cpe=f"cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*",
    )


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """No network, no real snapshots: each test names its own data."""
    reset_scan_warnings()
    monkeypatch.setattr(data, "synced_snapshot_path", lambda: tmp_path / "synced.json")
    monkeypatch.setattr(data, "bundled_snapshot_path", lambda: tmp_path / "bundled.json")
    monkeypatch.setattr(data, "_now", lambda: NOW)

    def _no_network(*_args, **_kwargs):
        raise httpx.ConnectError("network disabled in test")

    monkeypatch.setattr(data, "fetch_bytes", _no_network)
    monkeypatch.setattr("agent_bom.coverage._open_readonly_db", lambda: None)
    yield
    reset_scan_warnings()


def _live(monkeypatch, entries: dict | None = None, schedule: dict | None = None) -> list[str]:
    calls: list[str] = []

    def _fetch(url, **kwargs):
        calls.append(url)
        assert kwargs["timeout"] <= 30
        if url == data.SCHEDULE_URL:
            assert kwargs["max_bytes"] == data.MAX_SCHEDULE_BYTES
            return json.dumps(schedule or SCHEDULE).encode()
        assert kwargs["max_bytes"] == data.MAX_INDEX_BYTES
        return json.dumps(entries or INDEX).encode()

    monkeypatch.setattr(data, "fetch_bytes", _fetch)
    return calls


def _gaps() -> list[dict]:
    return [w for w in peek_coverage_warnings() if w.get("reason") == RUNTIME_COVERAGE_UNKNOWN]


def _eol() -> list[dict]:
    return [w for w in peek_coverage_warnings() if w.get("reason") == "runtime_end_of_life"]


# ── detection ──────────────────────────────────────────────────────────────


def test_only_the_generic_node_runtime_is_a_nodejs_runtime() -> None:
    assert is_nodejs_runtime(_node())
    assert not is_nodejs_runtime(Package(name="node", version="18.1.0", ecosystem="npm"))
    assert not is_nodejs_runtime(Package(name="nodejs", version="18.19.0", ecosystem="deb"))
    assert not is_nodejs_runtime(Package(name="cpython", version="3.14.8", ecosystem="generic"))


def test_runtime_coverage_treats_node_as_having_a_dedicated_source() -> None:
    assert detect_runtime_coverage_gaps([_node()], offline=True, conn=None) == []
    ruby = Package(name="ruby", version="3.4.11", ecosystem="generic", cpe="cpe:2.3:a:ruby-lang:ruby:3.4.11:*:*:*:*:*:*:*")
    assert [gap["release"] for gap in detect_runtime_coverage_gaps([ruby], offline=True, conn=None)] == ["ruby:3.4.11"]


# ── matching ───────────────────────────────────────────────────────────────


def test_old_release_gets_each_cve_with_the_fix_on_its_own_line() -> None:
    findings = {f.id: f for f in matching_findings(INDEX, _node("18.1.0"))}
    assert set(findings) == {"CVE-2025-0001", "CVE-2025-0002", "NSWG-COR-9", "CVE-2016-1669"}
    assert findings["CVE-2025-0001"].fixed_version == "18.20.9"
    assert findings["CVE-2025-0001"].severity == Severity.HIGH
    assert findings["CVE-2025-0001"].summary == "Two CVEs fixed by one release."
    assert findings["NSWG-COR-9"].fixed_version == "18.20.5"
    assert findings["NSWG-COR-9"].severity == Severity.UNKNOWN
    # the vulnerable range's own upper bound is the first unaffected release on the line
    assert findings["CVE-2016-1669"].fixed_version == "18.2.0"
    assert findings["CVE-2016-1669"].severity == Severity.CRITICAL
    for finding in findings.values():
        assert finding.advisory_sources == ["nodejs_security_wg"]
        assert finding.severity_source == "nodejs_security_wg"
    assert "https://github.com/nodejs/security-wg/blob/main/vuln/core/150.json" in findings["CVE-2025-0001"].references


def test_line_without_a_patched_release_has_no_cross_major_fix() -> None:
    findings = {f.id: f for f in matching_findings(INDEX, _node("20.11.0"))}
    assert set(findings) == {"CVE-2025-0001", "CVE-2025-0002"}
    assert findings["CVE-2025-0001"].fixed_version is None


def test_current_release_on_a_line_matches_exactly() -> None:
    assert [f.id for f in matching_findings(INDEX, _node("24.15.0"))] == ["CVE-2026-106072"]
    assert matching_findings(INDEX, _node("24.15.0"))[0].fixed_version == "24.22.1"
    assert matching_findings(INDEX, _node("24.22.1")) == []
    assert matching_findings(INDEX, _node("25.0.0")) == []


def test_windows_only_advisories_do_not_apply_to_a_posix_runtime() -> None:
    assert "CVE-2025-27210" not in {f.id for f in matching_findings(INDEX, _node("22.1.0"))}


def test_unparseable_installed_version_fails_closed() -> None:
    with pytest.raises(ValueError):
        matching_findings(INDEX, _node("24.15"))


# ── snapshot selection, freshness and failure handling ─────────────────────


@pytest.mark.asyncio
async def test_online_scan_uses_the_live_index_and_records_provenance(monkeypatch) -> None:
    calls = _live(monkeypatch)
    package = _node("24.15.0")
    assert await scan_packages([package]) >= 1
    assert calls == [data.INDEX_URL, data.SCHEDULE_URL]
    assert [v.id for v in package.vulnerabilities] == ["CVE-2026-106072"]
    assert package.vulnerabilities[0].fixed_version == "24.22.1"
    assert not _gaps()
    receipt = next(item for item in package.version_evidence if item["type"] == "runtime_advisory_lookup")
    assert receipt["url"] == data.INDEX_URL
    assert receipt["repository_url"] == "https://github.com/nodejs/security-wg"
    assert receipt["status"] == "live"
    assert receipt["checked_at"] == NOW.isoformat()
    assert receipt["advisory_count"] == 1
    assert receipt["assessment"] == "upstream_release_lookup_complete"
    assert len(receipt["sha256"]) == 64


@pytest.mark.asyncio
async def test_offline_scan_uses_a_fresh_synced_snapshot_without_network(monkeypatch, tmp_path) -> None:
    calls = _live(monkeypatch)
    _snapshot(tmp_path / "synced.json", fetched_at=NOW - timedelta(days=2))
    package = _node("18.1.0")
    await scan_nodejs_runtimes([package], offline=True)
    assert calls == []
    assert {v.id for v in package.vulnerabilities} >= {"CVE-2025-0001", "NSWG-COR-9"}
    assert not _gaps()
    receipt = next(item for item in package.version_evidence if item["type"] == "runtime_advisory_lookup")
    assert receipt["status"] == "synced_snapshot"
    assert receipt["checked_at"] == (NOW - timedelta(days=2)).isoformat()


@pytest.mark.asyncio
async def test_offline_scan_falls_back_to_the_bundled_snapshot(tmp_path) -> None:
    _snapshot(tmp_path / "bundled.json", fetched_at=NOW - timedelta(days=1))
    package = _node("24.22.1")
    await scan_nodejs_runtimes([package], offline=True)
    assert package.vulnerabilities == []
    assert not _gaps()
    receipt = next(item for item in package.version_evidence if item["type"] == "runtime_advisory_lookup")
    assert receipt["status"] == "bundled_snapshot"
    assert receipt["advisory_count"] == 0


@pytest.mark.asyncio
async def test_freshest_snapshot_wins(tmp_path) -> None:
    _snapshot(tmp_path / "bundled.json", fetched_at=NOW - timedelta(days=1))
    _snapshot(tmp_path / "synced.json", fetched_at=NOW - timedelta(days=5))
    package = _node("24.22.1")
    await scan_nodejs_runtimes([package], offline=True)
    receipt = next(item for item in package.version_evidence if item["type"] == "runtime_advisory_lookup")
    assert receipt["status"] == "bundled_snapshot"


@pytest.mark.asyncio
async def test_stale_snapshot_leaves_the_runtime_not_assessed(tmp_path) -> None:
    _snapshot(tmp_path / "bundled.json", fetched_at=NOW - timedelta(days=15))
    package = _node("18.1.0")
    await scan_nodejs_runtimes([package], offline=True)
    assert package.vulnerabilities == []
    (gap,) = _gaps()
    assert gap["release"] == "node:18.1.0"
    assert gap["ecosystem"] == "generic"
    assert "2026-10-27" in gap["detail"]
    assert not any(item["type"] == "runtime_advisory_lookup" for item in package.version_evidence)


@pytest.mark.asyncio
async def test_stale_threshold_follows_the_db_stale_days_setting(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENT_BOM_DB_STALE_DAYS", "30")
    _snapshot(tmp_path / "bundled.json", fetched_at=NOW - timedelta(days=15))
    await scan_nodejs_runtimes([_node("18.1.0")], offline=True)
    assert not _gaps()


@pytest.mark.asyncio
async def test_missing_snapshot_offline_is_not_assessed() -> None:
    package = _node("24.15.0")
    await scan_nodejs_runtimes([package], offline=True)
    assert [gap["release"] for gap in _gaps()] == ["node:24.15.0"]


@pytest.mark.asyncio
async def test_network_failure_without_a_fresh_snapshot_records_a_gap(tmp_path) -> None:
    _snapshot(tmp_path / "synced.json", fetched_at=NOW - timedelta(days=40))
    package = _node("24.15.0")
    await scan_packages([package])
    assert package.vulnerabilities == []
    (gap,) = _gaps()
    assert gap["release"] == "node:24.15.0"
    assert "network disabled" not in gap["detail"]  # sanitized: no raw transport text


@pytest.mark.asyncio
async def test_network_failure_with_a_fresh_snapshot_still_assesses(tmp_path) -> None:
    _snapshot(tmp_path / "synced.json", fetched_at=NOW - timedelta(days=3))
    package = _node("24.15.0")
    await scan_packages([package])
    assert [v.id for v in package.vulnerabilities] == ["CVE-2026-106072"]
    assert not _gaps()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entries",
    [
        {"1": {"cve": ["CVE-2026-1"], "vulnerable": "1.2.3 - 2.0.0", "patched": "", "affectedEnvironments": ["all"]}},
        {"1": {"cve": "CVE-2026-1", "vulnerable": "4.x", "patched": "", "affectedEnvironments": ["all"]}},
        {"1": {"cve": ["CVE-2026-1"], "patched": "^4.1.0", "affectedEnvironments": ["all"]}},
        {"x": {"cve": ["CVE-2026-1"], "vulnerable": "4.x", "patched": "", "affectedEnvironments": ["all"]}},
        {"1": {"cve": ["not-a-cve"], "vulnerable": "4.x", "patched": "", "affectedEnvironments": ["all"]}},
        {"1": {"cve": ["CVE-2026-1"], "vulnerable": "4.x", "patched": "", "affectedEnvironments": "all"}},
        {},
    ],
)
async def test_malformed_live_index_is_never_clean(monkeypatch, entries) -> None:
    monkeypatch.setattr(data, "fetch_bytes", lambda *_a, **_k: json.dumps(entries).encode())
    package = _node("24.15.0")
    await scan_packages([package])
    assert package.vulnerabilities == []
    assert [gap["release"] for gap in _gaps()] == ["node:24.15.0"]


@pytest.mark.asyncio
async def test_tampered_snapshot_entry_count_is_rejected(tmp_path) -> None:
    path = _snapshot(tmp_path / "bundled.json")
    payload = json.loads(path.read_text())
    payload["entries"].pop("201")
    path.write_text(json.dumps(payload))
    await scan_nodejs_runtimes([_node("24.15.0")], offline=True)
    assert [gap["release"] for gap in _gaps()] == ["node:24.15.0"]


@pytest.mark.asyncio
async def test_one_lookup_serves_every_node_runtime_in_the_scan(monkeypatch) -> None:
    calls = _live(monkeypatch)
    old, new = _node("18.1.0"), _node("24.15.0")
    await scan_packages([old, new])
    assert calls == [data.INDEX_URL, data.SCHEDULE_URL]
    assert old.vulnerabilities and new.vulnerabilities


# ── refresh path (`agent-bom db update`) ───────────────────────────────────


def test_sync_snapshot_writes_a_dated_validated_sidecar(monkeypatch, tmp_path) -> None:
    _live(monkeypatch)
    target = tmp_path / "db" / "nodejs_core_vulns.json"
    assert data.sync_snapshot(target) == len(INDEX)
    payload = json.loads(target.read_text())
    assert payload["end_of_life"]["18"] == "2025-04-30"
    assert payload["end_of_life"]["0.10"] == "2016-10-31"
    assert payload["schedule_url"] == data.SCHEDULE_URL
    assert payload["fetched_at"] == NOW.isoformat()
    assert payload["source_url"] == data.INDEX_URL
    assert payload["license"] == "MIT"
    assert payload["entry_count"] == len(INDEX)
    assert data.load_snapshot(target, origin="synced_snapshot").entries == INDEX


def test_failed_sync_keeps_the_previous_snapshot(monkeypatch, tmp_path) -> None:
    target = _snapshot(tmp_path / "synced.json", fetched_at=NOW - timedelta(days=3))
    before = target.read_text()
    monkeypatch.setattr(data, "fetch_bytes", lambda *_a, **_k: b"{not json")
    with pytest.raises(ValueError):
        data.sync_snapshot(target)
    assert target.read_text() == before


@pytest.mark.real_vuln_db_sync
def test_db_update_nodejs_source_refreshes_the_sidecar_next_to_the_db(monkeypatch, tmp_path) -> None:
    from agent_bom.db.sync import sync_db

    _live(monkeypatch)
    db_path = tmp_path / "vulns.db"
    results = sync_db(path=db_path, sources=["nodejs"])
    assert results == {"nodejs": len(INDEX)}
    payload = json.loads((tmp_path / data.SNAPSHOT_FILENAME).read_text())
    assert payload["entry_count"] == len(INDEX)


def test_nodejs_is_a_default_db_update_source() -> None:
    from agent_bom.db.sync import DEFAULT_SYNC_SOURCES

    assert "nodejs" in DEFAULT_SYNC_SOURCES


def test_offline_mode_blocks_the_live_fetch(monkeypatch) -> None:
    from agent_bom import http_client

    monkeypatch.setattr(http_client, "_OFFLINE", True)
    calls = _live(monkeypatch)
    with pytest.raises(http_client.OfflineModeError):
        data.fetch_index()
    assert calls == []


# ── bundled snapshot shipped in the wheel ──────────────────────────────────


def test_bundled_snapshot_is_valid_dated_and_from_the_official_source() -> None:
    bundled = Path(data.__file__).resolve().parents[1] / "data" / data.SNAPSHOT_FILENAME
    snapshot = data.load_snapshot(bundled, origin="bundled_snapshot")
    assert snapshot.fetched_at.tzinfo is not None
    assert len(snapshot.entries) >= 200
    payload = json.loads(bundled.read_text())
    assert payload["source_url"] == "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
    assert payload["license"] == "MIT"


# ── image scan end to end ──────────────────────────────────────────────────


def _image_node(version: str) -> Package:
    """The runtime component an official node image yields: ``ENV NODE_VERSION`` plus the binary."""
    from agent_bom.parsers.image_runtimes import finalize_image_runtimes, runtime_packages_from_config

    (package,) = runtime_packages_from_config({"config": {"Env": [f"NODE_VERSION={version}", "PATH=/usr/local/bin"]}})
    (package,) = finalize_image_runtimes([package])
    return package


@pytest.mark.asyncio
async def test_image_node_binary_is_assessed_end_to_end(monkeypatch) -> None:
    _live(monkeypatch)
    package = _image_node("24.15.0")
    assert is_nodejs_runtime(package)
    await scan_packages([package])
    assert [v.id for v in package.vulnerabilities] == ["CVE-2026-106072"]
    assert not _gaps()


@pytest.mark.parametrize(
    ("sources", "expected"),
    [
        (["nodejs_security_wg"], {"name": "Node.js security working group", "url": "https://github.com/nodejs/security-wg"}),
        (["nvidia_csaf"], {"name": "NVIDIA CSAF", "url": "https://www.nvidia.com/en-us/security/"}),
        (["osv", "nodejs_security_wg"], {"name": "OSV", "url": "https://osv.dev/vulnerability/CVE-2025-23085"}),
        (["osv"], {"name": "OSV", "url": "https://osv.dev/vulnerability/CVE-2025-23085"}),
    ],
)
def test_cyclonedx_names_the_feed_that_produced_the_finding(sources, expected) -> None:
    from agent_bom.models import Vulnerability
    from agent_bom.sbom_formats.cyclonedx import vulnerability_source

    vuln = Vulnerability(id="CVE-2025-23085", summary="x", severity=Severity.MEDIUM, advisory_sources=sources)
    assert vulnerability_source(vuln) == expected


def test_synced_snapshot_resolves_like_the_other_air_gap_sidecars(monkeypatch, tmp_path) -> None:
    from agent_bom.db.schema import DB_PATH

    monkeypatch.delenv("AGENT_BOM_VULN_DB_BUNDLE_DIR", raising=False)
    assert data.sidecar_dir() == DB_PATH.parent
    monkeypatch.setenv("AGENT_BOM_VULN_DB_BUNDLE_DIR", str(tmp_path / "bundle"))
    assert data.sidecar_dir() == tmp_path / "bundle"


# ── end-of-life release lines ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_end_of_life_line_keeps_its_findings_but_is_not_a_complete_assessment(tmp_path) -> None:
    from agent_bom.coverage import package_vulnerability_unassessed

    _snapshot(tmp_path / "synced.json")
    package = _node("18.1.0")
    await scan_nodejs_runtimes([package], offline=True)
    assert {v.id for v in package.vulnerabilities} >= {"CVE-2025-0001", "NSWG-COR-9"}
    assert not _gaps()
    (warning,) = _eol()
    assert warning["release"] == "node:18.1.0"
    assert warning["ecosystem"] == "generic"
    assert "2025-04-30" in warning["detail"]
    # findings stay countable: the package was assessed, just not completely
    assert package_vulnerability_unassessed(package, peek_coverage_warnings()) is False


@pytest.mark.asyncio
async def test_supported_line_has_no_end_of_life_warning(tmp_path) -> None:
    _snapshot(tmp_path / "synced.json")
    await scan_nodejs_runtimes([_node("24.15.0"), _node("22.1.0")], offline=True)
    assert not _eol()
    assert not _gaps()


@pytest.mark.asyncio
async def test_line_past_end_of_life_as_of_the_data_date_only(monkeypatch, tmp_path) -> None:
    # v20 ended 2026-04-30: data captured before then still covered it.
    _snapshot(tmp_path / "synced.json", fetched_at=datetime(2026, 4, 1, tzinfo=timezone.utc))
    monkeypatch.setattr(data, "_now", lambda: datetime(2026, 4, 2, tzinfo=timezone.utc))
    await scan_nodejs_runtimes([_node("20.11.0")], offline=True)
    assert not _eol()
    _snapshot(tmp_path / "synced.json", fetched_at=datetime(2026, 4, 30, tzinfo=timezone.utc))
    monkeypatch.setattr(data, "_now", lambda: datetime(2026, 5, 1, tzinfo=timezone.utc))
    await scan_nodejs_runtimes([_node("20.11.0")], offline=True)
    assert [w["release"] for w in _eol()] == ["node:20.11.0"]


@pytest.mark.asyncio
async def test_release_line_missing_from_the_schedule_is_flagged(tmp_path) -> None:
    _snapshot(tmp_path / "synced.json")
    await scan_nodejs_runtimes([_node("99.0.0")], offline=True)
    (warning,) = _eol()
    assert "schedule" in warning["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("schedule", [{}, {"v18": {"start": "2022-04-19"}}, {"v18": {"end": "not-a-date"}}, {"18": {"end": "2025-04-30"}}])
async def test_malformed_release_schedule_is_never_clean(monkeypatch, schedule) -> None:
    _live(monkeypatch, schedule=schedule)
    monkeypatch.setattr(data, "fetch_bytes", lambda url, **_k: json.dumps(schedule if url == data.SCHEDULE_URL else INDEX).encode())
    package = _node("24.15.0")
    await scan_packages([package])
    assert package.vulnerabilities == []
    assert [gap["release"] for gap in _gaps()] == ["node:24.15.0"]
