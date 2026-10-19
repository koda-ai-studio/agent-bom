"""A merged finding keeps the best known fix for the affected package.

Real shape: GHSA-29mw-wpgm-hmr9 (CVE-2020-28500) lists five affected entries,
mixing ``fixed`` ranges with ``last_affected``-only ranges for *other*
packages. The local DB row for CVE-2020-28500 has no fix (no range fix, or an
unverified range) and outranks the live GHSA record on severity, so the fix
must come from the cluster member that has one — never from another
package's range, never invented.
"""

from __future__ import annotations

import asyncio
import json
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.schema import init_db
from agent_bom.models import Package, Severity, Vulnerability


def _affected(name: str, ecosystem: str, end: dict, range_type: str = "SEMVER") -> dict:
    return {"package": {"name": name, "ecosystem": ecosystem}, "ranges": [{"type": range_type, "events": [{"introduced": "4.0.0"}, end]}]}


GHSA_29MW = {
    "id": "GHSA-29mw-wpgm-hmr9",
    "aliases": ["CVE-2020-28500"],
    "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
    "modified": "2025-09-29T21:12:31Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
    "affected": [
        _affected("lodash", "npm", {"fixed": "4.17.21"}),
        _affected("lodash-es", "npm", {"fixed": "4.17.21"}),
        _affected("lodash.trimend", "npm", {"last_affected": "4.5.1"}),
        _affected("lodash.trim", "npm", {"last_affected": "4.5.1"}),
        _affected("lodash-rails", "RubyGems", {"fixed": "4.17.21"}, "ECOSYSTEM"),
    ],
}


def test_fix_extraction_on_mixed_fixed_and_last_affected_entries():
    from agent_bom.scanners.osv import parse_fixed_version

    assert parse_fixed_version(GHSA_29MW, "lodash", "npm", current_version="4.17.20") == "4.17.21"
    # A last_affected-only entry has no fix; another package's 4.17.21 must not be borrowed.
    assert parse_fixed_version(GHSA_29MW, "lodash.trim", "npm", current_version="4.5.0") is None


def _cve_row(**overrides) -> Vulnerability:
    fields = {"id": "CVE-2020-28500", "summary": "ReDoS", "severity": Severity.HIGH, "cvss_score": 7.5, "fixed_version": None}
    return Vulnerability(**{**fields, **overrides})


def _ghsa_record(**overrides) -> Vulnerability:
    fields = {
        "id": "CVE-2020-28500",
        "aliases": ["GHSA-29mw-wpgm-hmr9"],
        "summary": "ReDoS",
        "severity": Severity.MEDIUM,
        "cvss_score": 5.3,
        "fixed_version": "4.17.21",
    }
    return Vulnerability(**{**fields, **overrides})


def test_merge_keeps_alias_fix_when_the_winning_record_has_none():
    from agent_bom.scanners.package_scan import merge_scanner_vulnerabilities

    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm", vulnerabilities=[_cve_row()])
    merge_scanner_vulnerabilities(pkg, [_ghsa_record()])

    [merged] = pkg.vulnerabilities
    assert merged.severity == Severity.HIGH
    assert merged.cvss_score == 7.5
    assert merged.fixed_version == "4.17.21"


def test_merge_never_invents_a_fix():
    from agent_bom.scanners.package_scan import merge_scanner_vulnerabilities

    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm", vulnerabilities=[_cve_row()])
    merge_scanner_vulnerabilities(pkg, [_ghsa_record(fixed_version=None)])

    assert pkg.vulnerabilities[0].fixed_version is None


def test_distro_empty_fix_stays_authoritative():
    """For release-scoped OS packages an empty fix means "no fix for this release"."""
    from agent_bom.scanners.package_scan import merge_scanner_vulnerabilities

    pkg = Package(name="openssl", version="3.0.11-1~deb12u2", ecosystem="deb", vulnerabilities=[_cve_row(id="CVE-2024-0001")])
    merge_scanner_vulnerabilities(pkg, [_ghsa_record(id="CVE-2024-0001", aliases=[], fixed_version="3.0.15-1")])

    assert pkg.vulnerabilities[0].fixed_version is None


# ── End to end: local CVE row without a fix + live GHSA record with one ──────


def _build_db(path: Path) -> Path:
    conn = init_db(path)
    try:
        conn.execute(
            "INSERT INTO vulns(id,summary,severity,cvss_score,fixed_version,aliases,source) VALUES (?,?,?,?,?,?,'ghsa')",
            ("CVE-2020-28500", "lodash ReDoS", "high", 7.5, "", "GHSA-29mw-wpgm-hmr9"),
        )
        conn.execute(
            "INSERT INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
            ("CVE-2020-28500", "npm", "lodash", "4.0.0", ""),
        )
        synced = (datetime.now(timezone.utc) - timedelta(days=61)).isoformat()
        conn.execute("INSERT INTO sync_meta(source,last_synced,record_count) VALUES ('osv',?,1)", (synced,))
        conn.commit()
    finally:
        conn.close()
    return path


async def _osv(_client, method: str, url: str, **kwargs):
    request = httpx.Request(method, url)
    if url.endswith("/querybatch"):
        results = [{"vulns": [{"id": GHSA_29MW["id"], "modified": GHSA_29MW["modified"]}]} for _ in kwargs["json"]["queries"]]
        return httpx.Response(200, json={"results": results}, request=request)
    if url.endswith(f"/vulns/{GHSA_29MW['id']}"):
        return httpx.Response(200, json=GHSA_29MW, request=request)
    return httpx.Response(404, json={}, request=request)


@pytest.fixture
def live_ghsa(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _refuse(*_args, **_kwargs):
        raise AssertionError("test attempted a real network connection")

    @asynccontextmanager
    async def _client(*_args, **_kwargs):
        yield object()

    async def _no_ghsa(_packages):
        return 0

    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", _build_db(tmp_path / "vulns.db"))
    monkeypatch.setattr("agent_bom.scanners.create_client", _client)
    monkeypatch.setattr("agent_bom.scanners.request_with_retry", _osv)
    monkeypatch.setattr("agent_bom.scanners._get_scan_cache", lambda: None)
    monkeypatch.setattr("agent_bom.scanners.package_scan._check_ghsa", _no_ghsa)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", raising=False)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)


def _cli_finding() -> dict:
    result = CliRunner().invoke(main, ["check", "lodash@4.17.20", "--ecosystem", "npm", "--format", "json"])
    [finding] = json.loads(result.output)["vulnerability_details"]
    return finding


def _mcp_finding() -> dict:
    from agent_bom.mcp_tools.scanning import check_impl

    payload = json.loads(
        asyncio.run(
            check_impl(
                package="lodash@4.17.20",
                ecosystem="npm",
                _validate_ecosystem=lambda ecosystem: ecosystem,
                _truncate_response=lambda response: response,
            )
        )
    )
    [finding] = payload["vulnerability_details"]
    return finding


def test_local_cve_row_without_fix_keeps_live_ghsa_fix(live_ghsa):
    finding = _cli_finding()

    assert finding["id"] == "CVE-2020-28500"
    assert "GHSA-29mw-wpgm-hmr9" in finding["aliases"]
    assert finding["fixed_version"] == "4.17.21"


def test_cli_and_mcp_report_the_same_fix(live_ghsa):
    cli, mcp = _cli_finding(), _mcp_finding()

    assert cli["fixed_version"] == mcp["fixed_version"] == "4.17.21"
    assert (cli["severity"], cli["cvss_score"]) == (mcp["severity"], mcp["cvss_score"])
