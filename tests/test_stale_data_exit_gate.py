"""Fail closed when nothing trips the gate but the data behind it is incomplete.

Owner decision: an outdated local DB that OSV did not back (offline, or OSV
did not answer) is an incomplete result. ``check`` exits 2 (its documented
"incomplete" code), ``scan`` fails closed through its incomplete ``scan_run``
outcome (exit 1), and MCP/REST report a structured ``incomplete`` status.
Real findings keep their exit codes. ``--allow-stale-db`` /
``AGENT_BOM_ALLOW_STALE_DB`` is the explicit air-gap opt-out, and
``--require-fresh-db`` / ``AGENT_BOM_REQUIRE_FRESH_DB`` is honoured by ``check``
(exit 3) as it already is by ``scan``.
"""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from tests.test_stale_local_db_check import LIVE_OSV, _use_db

CLEAN = "lodash@4.17.21"
VULNERABLE = "lodash@4.17.20"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """No sockets, no gate env, and an OSV that answers (tests override it to stay silent)."""

    def _refuse(*_args, **_kwargs):
        raise AssertionError("test attempted a real network connection")

    async def _answer(_packages):
        from agent_bom.scanners.state import _bump_scan_perf

        _bump_scan_perf("osv_batches_answered", 1)
        return LIVE_OSV

    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", _answer)
    monkeypatch.delenv("AGENT_BOM_ALLOW_STALE_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_REQUIRE_FRESH_DB", raising=False)


def _check(spec: str, *extra: str) -> tuple[int, dict]:
    result = CliRunner().invoke(main, ["check", spec, "--ecosystem", "npm", "--format", "json", *extra])
    return result.exit_code, json.loads(result.output)


def _check_text(spec: str, *extra: str) -> tuple[int, str]:
    result = CliRunner().invoke(main, ["check", spec, "--ecosystem", "npm", "--no-color", *extra])
    return result.exit_code, result.output


def _mcp(spec: str, *, offline: bool) -> dict:
    from agent_bom.mcp_tools.scanning import check_impl

    return json.loads(
        asyncio.run(
            check_impl(
                package=spec,
                ecosystem="npm",
                offline=offline,
                _validate_ecosystem=lambda value: value,
                _truncate_response=lambda value: value,
            )
        )
    )


def _silent_osv(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _silent(_packages):
        return {}

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", _silent)


# ── check: CLI exit codes ────────────────────────────────────────────────────


def test_stale_offline_clean_check_exits_incomplete(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    exit_code, payload = _check(CLEAN, "--offline")
    text_code, output = _check_text(CLEAN, "--offline")

    assert exit_code == 2 == text_code
    assert payload["verdict"] == "incomplete"
    assert payload["canonical_verdict"] == "incomplete"
    assert payload["completeness"]["status"] == "incomplete"
    assert "61 days old" in payload["message"]
    assert "⚠" in output and "--allow-stale-db" in output


def test_stale_online_without_osv_answer_exits_incomplete(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)
    _silent_osv(monkeypatch)

    exit_code, payload = _check(CLEAN)

    assert exit_code == 2
    assert payload["verdict"] == "incomplete"


@pytest.mark.parametrize("opt_out", ["flag", "env"])
def test_allow_stale_db_opts_out(monkeypatch, tmp_path, opt_out):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)
    extra = ["--offline"]
    if opt_out == "flag":
        extra.append("--allow-stale-db")
    else:
        monkeypatch.setenv("AGENT_BOM_ALLOW_STALE_DB", "1")

    exit_code, payload = _check(CLEAN, *extra)

    assert exit_code == 0
    assert payload["verdict"] == "clean"
    # The opt-out accepts the data; it does not pretend the data is complete.
    assert payload["completeness"]["status"] == "incomplete"


def test_real_findings_keep_exit_1(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    exit_code, payload = _check(VULNERABLE, "--offline")

    assert exit_code == 1
    assert payload["verdict"] == "unsafe"


@pytest.mark.parametrize("extra", [["--fail-on-severity", "critical"], ["--exit-zero"]])
def test_findings_below_the_gate_on_incomplete_data_exit_incomplete(monkeypatch, tmp_path, extra):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    exit_code, payload = _check(VULNERABLE, "--offline", *extra)

    assert exit_code == 2
    assert payload["verdict"] == "incomplete"
    assert payload["vulnerability_count"] == 3


def test_fresh_offline_clean_check_still_exits_0(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=0)

    exit_code, payload = _check(CLEAN, "--offline")

    assert exit_code == 0
    assert payload["verdict"] == "clean"


@pytest.mark.parametrize("gate", ["flag", "env"])
def test_check_honours_require_fresh_db(monkeypatch, tmp_path, gate):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)
    extra = []
    if gate == "flag":
        extra.append("--require-fresh-db")
    else:
        monkeypatch.setenv("AGENT_BOM_REQUIRE_FRESH_DB", "1")

    exit_code, payload = _check(CLEAN, *extra)

    assert exit_code == 3
    assert payload["exit_code"] == 3
    assert "--require-fresh-db" in payload["message"]


def test_require_fresh_db_passes_a_fresh_db(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=0)

    exit_code, _payload = _check(CLEAN, "--require-fresh-db")

    assert exit_code == 0


# ── MCP / REST: structured status ────────────────────────────────────────────


def test_mcp_check_reports_incomplete_status(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    payload = _mcp(CLEAN, offline=True)

    assert payload["status"] == "incomplete"
    assert payload["canonical_verdict"] == "incomplete"
    assert "61 days old" in payload["message"]

    monkeypatch.setenv("AGENT_BOM_ALLOW_STALE_DB", "1")
    assert _mcp(CLEAN, offline=True)["status"] == "clean"


def test_mcp_check_keeps_real_findings_vulnerable(monkeypatch, tmp_path):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)

    assert _mcp(VULNERABLE, offline=True)["status"] == "vulnerable"


# ── scan: shared scanner signal → incomplete scan outcome ────────────────────


def test_scanner_records_stale_data_coverage_issue(monkeypatch, tmp_path):
    from agent_bom.models import Package
    from agent_bom.scanners import ScanOptions, consume_coverage_warnings, reset_scan_warnings, scan_packages

    _use_db(monkeypatch, tmp_path, synced_days_ago=61)
    reset_scan_warnings()
    asyncio.run(scan_packages([Package(name="lodash", version="4.17.21", ecosystem="npm")], options=ScanOptions(offline=True)))

    [warning] = [w for w in consume_coverage_warnings() if w.get("kind") == "stale_local_data"]
    assert "61 days old" in warning["detail"]

    monkeypatch.setenv("AGENT_BOM_ALLOW_STALE_DB", "1")
    reset_scan_warnings()
    asyncio.run(scan_packages([Package(name="lodash", version="4.17.21", ecosystem="npm")], options=ScanOptions(offline=True)))
    assert not [w for w in consume_coverage_warnings() if w.get("kind") == "stale_local_data"]


def test_scanner_records_nothing_when_osv_answered(monkeypatch, tmp_path):
    from agent_bom.models import Package
    from agent_bom.scanners import ScanOptions, consume_coverage_warnings, reset_scan_warnings, scan_packages

    _use_db(monkeypatch, tmp_path, synced_days_ago=61)
    reset_scan_warnings()
    asyncio.run(scan_packages([Package(name="lodash", version="4.17.21", ecosystem="npm")], options=ScanOptions(offline=False)))

    assert not [w for w in consume_coverage_warnings() if w.get("kind") == "stale_local_data"]


def _lockfile_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}}))
    (project / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {"": {"name": "demo", "version": "1.0.0"}, "node_modules/lodash": {"version": "4.17.21"}},
            }
        )
    )
    return project


@pytest.mark.parametrize("allow", [False, True])
def test_scan_offline_on_stale_db_fails_closed_unless_allowed(monkeypatch, tmp_path, allow):
    _use_db(monkeypatch, tmp_path, synced_days_ago=61)
    project = _lockfile_project(tmp_path)
    args = ["scan", str(project), "--offline", "--no-discover", "--no-auto-update-db", "--format", "json", "--quiet"]
    if allow:
        args.append("--allow-stale-db")

    result = CliRunner().invoke(main, args)

    assert result.exit_code == (0 if allow else 1), result.output
