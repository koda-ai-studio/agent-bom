"""Stale fused alias groups in the local DB must not collapse distinct advisories.

Fixture mirrors a real stale DB: for a while upstream alias groups linked
CVE-2021-23337/GHSA-35jh with CVE-2026-4800/GHSA-r5fr (and CVE-2025-13465/
GHSA-xxjr with CVE-2026-2950/GHSA-f23m). Every row of each group stores the
whole fused group as its aliases. Live OSV now returns five separate
advisories, each with exactly one CVE alias.
"""

from __future__ import annotations

import asyncio
import json
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.schema import init_db
from tests.test_live_osv_hydration_merge import _OSVServer

# (row id, fused aliases, introduced, fixed) — aliases exactly as the stale DB stored them.
FUSED_ROWS = [
    ("GHSA-29mw-wpgm-hmr9", "CVE-2020-28500", "4.0.0", "4.17.21"),
    ("CVE-2021-23337", "CVE-2026-4800,GHSA-35jh-r3h4-6jhm,GHSA-r5fr-rjxr-66jc", "0", "4.17.21"),
    ("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337,CVE-2026-4800,GHSA-r5fr-rjxr-66jc", "0", "4.17.21"),
    ("CVE-2026-4800", "CVE-2021-23337,GHSA-35jh-r3h4-6jhm,GHSA-r5fr-rjxr-66jc", "4.0.0", "4.18.0"),
    ("GHSA-r5fr-rjxr-66jc", "CVE-2021-23337,CVE-2026-4800,GHSA-35jh-r3h4-6jhm", "4.0.0", "4.18.0"),
    ("CVE-2025-13465", "CVE-2026-2950,GHSA-f23m-r3pf-42rh,GHSA-xxjr-mmjv-4gpg", "4.0.0", "4.17.23"),
    ("GHSA-xxjr-mmjv-4gpg", "CVE-2025-13465,CVE-2026-2950,GHSA-f23m-r3pf-42rh", "4.0.0", "4.17.23"),
    ("CVE-2026-2950", "CVE-2025-13465,GHSA-f23m-r3pf-42rh,GHSA-xxjr-mmjv-4gpg", "0", "4.18.0"),
    ("GHSA-f23m-r3pf-42rh", "CVE-2025-13465,CVE-2026-2950,GHSA-xxjr-mmjv-4gpg", "0", "4.18.0"),
]

EXPECTED_FIX = {
    "CVE-2020-28500": "4.17.21",
    "CVE-2021-23337": "4.17.21",
    "CVE-2025-13465": "4.17.23",
    "CVE-2026-2950": "4.18.0",
    "CVE-2026-4800": "4.18.0",
}
EXPECTED_GHSA = {
    "CVE-2020-28500": "GHSA-29mw-wpgm-hmr9",
    "CVE-2021-23337": "GHSA-35jh-r3h4-6jhm",
    "CVE-2025-13465": "GHSA-xxjr-mmjv-4gpg",
    "CVE-2026-2950": "GHSA-f23m-r3pf-42rh",
    "CVE-2026-4800": "GHSA-r5fr-rjxr-66jc",
}


def _build_fused_db(path: Path) -> Path:
    conn = init_db(path)
    try:
        for vuln_id, aliases, introduced, fixed in FUSED_ROWS:
            conn.execute(
                "INSERT INTO vulns(id,summary,severity,cvss_score,fixed_version,aliases,source) VALUES (?,?,?,?,?,?,'osv')",
                (vuln_id, f"lodash advisory {vuln_id}", "high", 7.5, fixed, aliases),
            )
            conn.execute(
                "INSERT INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
                (vuln_id, "npm", "lodash", introduced, fixed),
            )
        synced = (datetime.now(timezone.utc) - timedelta(days=61)).isoformat()
        conn.execute("INSERT INTO sync_meta(source,last_synced,record_count) VALUES ('osv',?,?)", (synced, len(FUSED_ROWS)))
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _OSVServer:
    def _refuse(*_args, **_kwargs):
        raise AssertionError("test attempted a real network connection")

    @asynccontextmanager
    async def _client(*_args, **_kwargs):
        yield object()

    async def _no_ghsa(_packages):
        return 0

    server = _OSVServer()
    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", _build_fused_db(tmp_path / "vulns.db"))
    monkeypatch.setattr("agent_bom.scanners.create_client", _client)
    monkeypatch.setattr("agent_bom.scanners.request_with_retry", server.request)
    monkeypatch.setattr("agent_bom.scanners._get_scan_cache", lambda: None)
    monkeypatch.setattr("agent_bom.scanners.package_scan._check_ghsa", _no_ghsa)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", raising=False)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)
    return server


def _cli(*extra: str) -> dict:
    result = CliRunner().invoke(main, ["check", "lodash@4.17.20", "--ecosystem", "npm", "--format", "json", *extra])
    return json.loads(result.output)


def _mcp(offline: bool = False) -> dict:
    from agent_bom.mcp_tools.scanning import check_impl

    return json.loads(
        asyncio.run(
            check_impl(
                package="lodash@4.17.20",
                ecosystem="npm",
                offline=offline,
                _validate_ecosystem=lambda ecosystem: ecosystem,
                _truncate_response=lambda response: response,
            )
        )
    )


def _by_id(payload: dict) -> dict[str, dict]:
    return {detail["id"]: detail for detail in payload["vulnerability_details"]}


def test_live_alias_sets_split_stale_fused_local_groups():
    findings = _by_id(_cli())

    assert set(findings) == set(EXPECTED_FIX)
    for cve, fixed in EXPECTED_FIX.items():
        assert findings[cve]["fixed_version"] == fixed, (cve, findings[cve]["fixed_version"])
        assert EXPECTED_GHSA[cve] in findings[cve]["aliases"]
        foreign = {other for other in EXPECTED_FIX if other != cve} | {g for c, g in EXPECTED_GHSA.items() if c != cve}
        assert not foreign & set(findings[cve]["aliases"]), (cve, findings[cve]["aliases"])


def test_mcp_check_matches_cli_on_fused_fixture():
    cli = _by_id(_cli())
    mcp = _by_id(_mcp())

    assert set(mcp) == set(cli)
    assert {k: v["fixed_version"] for k, v in mcp.items()} == {k: v["fixed_version"] for k, v in cli.items()}
    assert {k: sorted(v["aliases"]) for k, v in mcp.items()} == {k: sorted(v["aliases"]) for k, v in cli.items()}


def test_offline_fused_rows_never_borrow_another_advisorys_fix():
    findings = _by_id(_cli("--offline"))

    for cve, fixed in EXPECTED_FIX.items():
        assert cve in findings, sorted(findings)
        assert findings[cve]["fixed_version"] == fixed, (cve, findings[cve]["fixed_version"])
    assert not ({"CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"} & set(findings["CVE-2021-23337"]["aliases"]))


def test_distinct_primary_cves_never_merge_through_a_shared_alias():
    from agent_bom.models import Severity, Vulnerability
    from agent_bom.scanners.advisory_merge import merge_advisory_clusters

    first = Vulnerability(id="CVE-2030-0001", summary="a", severity=Severity.HIGH, aliases=["GHSA-shared"], fixed_version="1.0")
    second = Vulnerability(id="CVE-2030-0002", summary="b", severity=Severity.LOW, aliases=["GHSA-shared"], fixed_version="2.0")
    bridge = Vulnerability(id="GHSA-shared", summary="c", severity=Severity.MEDIUM)

    merged = {record.id: record for record in merge_advisory_clusters([first, second, bridge])}

    assert {"CVE-2030-0001", "CVE-2030-0002"} <= set(merged)
    assert merged["CVE-2030-0001"].fixed_version == "1.0"
    assert merged["CVE-2030-0002"].fixed_version == "2.0"


def test_own_cve_id_wins_over_a_cve_alias():
    from agent_bom.advisory_ids import canonical_vulnerability_id

    canonical, aliases = canonical_vulnerability_id("CVE-2021-23337", ["CVE-2026-4800", "GHSA-35jh-r3h4-6jhm"])

    assert canonical == "CVE-2021-23337"
    assert aliases == ["CVE-2026-4800", "GHSA-35jh-r3h4-6jhm"]
