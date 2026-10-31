"""A stale local vuln DB must never produce a confident, silently-incomplete check.

Fixture: a real SQLite advisory DB whose recorded sync is older than the
threshold ``agent-bom db freshness`` warns on, and which lacks advisories that
the (mocked) live OSV response carries.
"""

from __future__ import annotations

import asyncio
import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.schema import init_db

LOCAL_IDS = ("CVE-2020-28500", "CVE-2021-23337", "CVE-2025-13465")
LIVE_ONLY_IDS = ("CVE-2026-2950", "CVE-2026-4800")
PKG_KEY = "npm:lodash@4.17.20"


def _osv_record(vuln_id: str, *, alias: str | None = None) -> dict:
    record = {
        "id": vuln_id,
        "summary": f"lodash advisory {vuln_id}",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.18.0"}]}],
            }
        ],
        "database_specific": {"severity": "HIGH"},
    }
    if alias:
        record["aliases"] = [alias]
    return record


# The live feed reports one local advisory under its GHSA id with the CVE as an
# alias, so the merge must dedupe by alias, not only by primary id.
LIVE_OSV = {
    PKG_KEY: [
        _osv_record("CVE-2020-28500"),
        _osv_record("GHSA-29mw-wpgm-hmr9", alias="CVE-2021-23337"),
        _osv_record("CVE-2025-13465"),
        *(_osv_record(vuln_id) for vuln_id in LIVE_ONLY_IDS),
    ]
}


def _build_db(path: Path, *, synced_days_ago: int) -> Path:
    conn = init_db(path)
    try:
        for vuln_id in LOCAL_IDS:
            conn.execute(
                "INSERT INTO vulns(id,summary,severity,cvss_score,source) VALUES (?,?,?,?,'osv')",
                (vuln_id, f"lodash advisory {vuln_id}", "high", 7.5),
            )
            conn.execute(
                "INSERT INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
                (vuln_id, "npm", "lodash", "0", "4.17.21"),
            )
        synced = (datetime.now(timezone.utc) - timedelta(days=synced_days_ago)).isoformat()
        conn.execute("INSERT INTO sync_meta(source,last_synced,record_count) VALUES ('osv',?,?)", (synced, len(LOCAL_IDS)))
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*_args, **_kwargs):
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)


@pytest.fixture
def osv(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    async def _answer(_packages):
        from agent_bom.scanners.state import _bump_scan_perf

        _bump_scan_perf("osv_batches_answered", 1)
        return LIVE_OSV

    mock = AsyncMock(side_effect=_answer)
    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", mock)
    return mock


def _use_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, synced_days_ago: int, max_age_hours: str | None = None) -> None:
    db = _build_db(tmp_path / "vulns.db", synced_days_ago=synced_days_ago)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db)
    if max_age_hours is None:
        monkeypatch.delenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", max_age_hours)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)


def _cli_json(*extra: str) -> tuple[int, dict]:
    result = CliRunner().invoke(main, ["check", "lodash@4.17.20", "--ecosystem", "npm", "--format", "json", *extra])
    return result.exit_code, json.loads(result.output)


def _cli_text(*extra: str) -> tuple[int, str]:
    result = CliRunner().invoke(main, ["check", "lodash@4.17.20", "--ecosystem", "npm", "--no-color", *extra])
    return result.exit_code, result.output


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


def _ids(payload: dict) -> set[str]:
    return {detail["id"] for detail in payload["vulnerability_details"]}


# The danger-but-not-stale case is the reported field failure: `db freshness`
# says "results may miss recent CVEs" while the scanner trusted the cache.
@pytest.mark.parametrize("max_age_hours", [None, "2000"])
def test_stale_db_online_merges_live_osv_without_duplicates(monkeypatch, tmp_path, osv, max_age_hours):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61, max_age_hours=max_age_hours)

    exit_code, payload = _cli_json()

    assert osv.await_count == 1
    assert exit_code == 1
    assert _ids(payload) == {*LOCAL_IDS, *LIVE_ONLY_IDS}
    assert payload["vulnerability_count"] == 5
    assert payload["vuln_data_freshness"]["age_days"] == 61
    assert payload["completeness"]["status"] == "complete"
    assert "61" in payload["completeness"]["reason"]


def test_stale_db_online_text_states_freshness_and_never_checkmarks_local_hits(monkeypatch, tmp_path, osv):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    exit_code, output = _cli_text()

    assert exit_code == 1
    assert "✓ Local DB" not in output
    assert "61 days old" in output
    assert "5 vulnerabilities found" in output


def test_stale_db_offline_warns_and_marks_incomplete(monkeypatch, tmp_path, osv):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    exit_code, payload = _cli_json("--offline")

    assert osv.await_count == 0
    assert exit_code == 1
    assert _ids(payload) == set(LOCAL_IDS)
    assert payload["completeness"]["status"] == "incomplete"
    assert "61 days old" in payload["completeness"]["reason"]
    assert payload["vuln_data_freshness"]["stale"] is True

    _code, output = _cli_text("--offline")
    assert "✓" not in output
    assert "may be incomplete" in output
    assert "61 days old" in output


def test_stale_db_network_failure_marks_incomplete(monkeypatch, tmp_path):
    from agent_bom.scanners.osv import _record_unavailable_osv

    async def _failing_osv(packages):
        _record_unavailable_osv(packages, "circuit_open")
        return {}

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", _failing_osv)
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    _exit_code, payload = _cli_json()

    assert _ids(payload) == set(LOCAL_IDS)
    assert payload["completeness"]["status"] == "incomplete"
    assert "61 days old" in payload["completeness"]["reason"]


def test_stale_db_offline_clean_package_has_no_checkmark(monkeypatch, tmp_path, osv):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    result = CliRunner().invoke(main, ["check", "lodash@4.17.21", "--ecosystem", "npm", "--no-color", "--offline"])

    # Fails closed as incomplete (exit 2); --allow-stale-db is the explicit opt-out.
    assert result.exit_code == 2, result.output
    assert "✓" not in result.output
    assert "incomplete" in result.output

    allowed = CliRunner().invoke(main, ["check", "lodash@4.17.21", "--ecosystem", "npm", "--no-color", "--offline", "--allow-stale-db"])
    assert allowed.exit_code == 0, allowed.output
    assert "✓" not in allowed.output
    assert "may be incomplete" in allowed.output


def test_fresh_db_makes_no_network_call(monkeypatch, tmp_path, osv):
    _use_db(monkeypatch, tmp_path, synced_days_ago=0)

    exit_code, payload = _cli_json()

    assert osv.await_count == 0
    assert exit_code == 1
    assert _ids(payload) == set(LOCAL_IDS)
    assert payload["completeness"] == {"status": "complete", "reason": ""}
    assert payload["vuln_data_freshness"]["stale"] is False


@pytest.mark.parametrize("offline", [False, True])
def test_mcp_check_matches_cli_for_stale_fixture(monkeypatch, tmp_path, osv, offline):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    _code, cli_payload = _cli_json(*(["--offline"] if offline else []))
    mcp_payload = _mcp(offline=offline)

    assert _ids(mcp_payload) == _ids(cli_payload)
    for field in ("vulnerability_count", "completeness", "vuln_data_freshness", "canonical_verdict"):
        assert mcp_payload[field] == cli_payload[field], field


def test_mcp_scan_report_carries_vuln_data_freshness(monkeypatch, tmp_path):
    from agent_bom.mcp_server_scan import _package_spec_agent
    from agent_bom.mcp_tools.scanning import scan_impl
    from agent_bom.parsers import extract_packages

    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    async def _pipeline(*_args, **_kwargs):
        agent, _warnings = _package_spec_agent("lodash@4.17.20", ecosystem="npm")
        for server in agent.mcp_servers:
            server.packages = server.packages or extract_packages(server)
        return [agent], [], [], ["mcp_package"]

    payload = json.loads(
        asyncio.run(
            scan_impl(package="lodash@4.17.20", ecosystem="npm", offline=True, _run_scan_pipeline=_pipeline, _truncate_response=lambda r: r)
        )
    )

    assert "vuln_data_freshness" in payload, payload
    freshness = payload["vuln_data_freshness"]
    assert freshness["mode"] == "offline"
    assert freshness["age_days"] == 61
    assert freshness["stale"] is True


def _mcp_scan_payload() -> dict:
    from agent_bom.mcp_server_scan import _package_spec_agent
    from agent_bom.mcp_tools.scanning import scan_impl
    from agent_bom.parsers import extract_packages

    async def _pipeline(*_args, **_kwargs):
        agent, _warnings = _package_spec_agent("lodash@4.17.20", ecosystem="npm")
        for server in agent.mcp_servers:
            server.packages = server.packages or extract_packages(server)
        return [agent], [], [], ["mcp_package"]

    return json.loads(
        asyncio.run(
            scan_impl(package="lodash@4.17.20", ecosystem="npm", offline=True, _run_scan_pipeline=_pipeline, _truncate_response=lambda r: r)
        )
    )


def test_mcp_scan_reads_freshness_through_the_module_at_call_time(monkeypatch, tmp_path):
    import agent_bom.mcp_tools.scanning  # noqa: F401 - imported before the patch, as in a long-lived server

    _use_db(monkeypatch, tmp_path, synced_days_ago=0)
    monkeypatch.setattr("agent_bom.vuln_freshness.compute_freshness", lambda **_kwargs: None)

    assert _mcp_scan_payload().get("vuln_data_freshness") is None


def test_mcp_scan_uses_current_freshness_snapshot(monkeypatch, tmp_path):
    import agent_bom.mcp_tools.scanning  # noqa: F401 - import before replacing the reader
    from agent_bom.scanners import local_data_freshness
    from agent_bom.vuln_freshness import compute_freshness

    _use_db(monkeypatch, tmp_path, synced_days_ago=61)
    snapshot = compute_freshness(offline=True)
    calls = []

    def current_snapshot(offline):
        calls.append(offline)
        return snapshot

    monkeypatch.setattr(local_data_freshness, "freshness_snapshot", current_snapshot)
    payload = _mcp_scan_payload()
    assert calls == [True]
    assert payload["vuln_data_freshness"] == snapshot.to_dict()


def test_mcp_scan_survives_a_freshness_probe_that_raises(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=0)

    def _boom(**_kwargs):
        raise RuntimeError("freshness probe exploded")

    monkeypatch.setattr("agent_bom.vuln_freshness.compute_freshness", _boom)

    assert _mcp_scan_payload().get("vuln_data_freshness") is None


# ── Fail closed when freshness cannot be trusted ─────────────────────────────


def _newer_schema(path: Path) -> None:
    import sqlite3

    from agent_bom.db.schema import CODE_SCHEMA_VERSION

    conn = sqlite3.connect(path)
    conn.execute("UPDATE schema_version SET version = ?", (CODE_SCHEMA_VERSION + 1,))
    conn.commit()
    conn.close()


def _unreadable_sync_meta(path: Path) -> None:
    """Keep ``last_synced`` (what the scanner's DB gate reads) but break the freshness read."""
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("ALTER TABLE sync_meta RENAME COLUMN record_count TO records")
    conn.commit()
    conn.close()


@pytest.mark.parametrize("synced_days_ago", [0, 61])
def test_newer_schema_db_forces_live_osv_and_says_why(monkeypatch, tmp_path, osv, synced_days_ago):
    _use_db(monkeypatch, tmp_path, synced_days_ago=synced_days_ago)
    _newer_schema(tmp_path / "vulns.db")

    _code, payload = _cli_json()

    assert osv.await_count == 1
    assert _ids(payload) == {*LOCAL_IDS, *LIVE_ONLY_IDS}
    assert "newer than this agent-bom" in payload["vuln_data_freshness"]["integrity_issue"]
    assert payload["completeness"]["status"] == "complete"
    assert "newer than this agent-bom" in payload["completeness"]["reason"]


def test_newer_schema_db_offline_is_incomplete(monkeypatch, tmp_path, osv):
    _use_db(monkeypatch, tmp_path, synced_days_ago=0)
    _newer_schema(tmp_path / "vulns.db")

    _code, payload = _cli_json("--offline")
    _text_code, output = _cli_text("--offline")

    assert osv.await_count == 0
    assert payload["completeness"]["status"] == "incomplete"
    assert "newer than this agent-bom" in payload["completeness"]["reason"]
    assert "✓" not in output
    assert "newer than this agent-bom" in output


def test_unreadable_freshness_metadata_forces_live_osv(monkeypatch, tmp_path, osv):
    _use_db(monkeypatch, tmp_path, synced_days_ago=0)
    _unreadable_sync_meta(tmp_path / "vulns.db")

    _code, payload = _cli_json()

    assert osv.await_count == 1
    assert _ids(payload) == {*LOCAL_IDS, *LIVE_ONLY_IDS}
    assert payload["vuln_data_freshness"]["mode"] == "local"
    assert payload["vuln_data_freshness"]["integrity_issue"]

    _offline_code, offline_payload = _cli_json("--offline")
    assert offline_payload["completeness"]["status"] == "incomplete"


def test_freshness_probe_that_raises_fails_closed(monkeypatch, tmp_path, osv):
    _use_db(monkeypatch, tmp_path, synced_days_ago=0)

    def _boom(**_kwargs):
        raise RuntimeError("freshness probe exploded")

    monkeypatch.setattr("agent_bom.vuln_freshness.compute_freshness", _boom)

    exit_code, payload = _cli_json()
    assert exit_code == 1
    assert osv.await_count == 1
    assert _ids(payload) == {*LOCAL_IDS, *LIVE_ONLY_IDS}
    assert payload["vuln_data_freshness"] is None
    assert payload["completeness"]["status"] == "complete"

    _offline_code, offline_payload = _cli_json("--offline")
    assert offline_payload["completeness"]["status"] == "incomplete"
    assert _ids(_mcp(offline=True)) == _ids(offline_payload)
