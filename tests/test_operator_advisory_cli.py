"""`agent-bom db advisory` and the MCP intel_lookup view of operator advisories."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom import history
from agent_bom.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "php2shell" / "operator-advisory.json"


def _report(version: str) -> dict:
    package = {"name": "php", "version": version, "ecosystem": "generic", "cpe": f"cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"}
    return {
        "ai_bom_version": "1",
        "scan_id": f"scan-{version}",
        "agents": [{"name": "image", "mcp_servers": [{"name": "php:8.3", "packages": [package]}]}],
    }


@pytest.fixture()
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
    return tmp_path


def _run(*args: str):
    return CliRunner().invoke(main, ["db", "advisory", *args], catch_exceptions=False)


def test_add_list_match_remove_round_trip(state: Path) -> None:
    assert _run("add", "--file", str(FIXTURE)).exit_code == 0
    listed = json.loads(_run("list", "--format", "json").output)
    assert [row["id"] for row in listed["advisories"]] == ["CVE-2026-109618"]

    history.save_report(_report("8.3.30"))
    matched = _run("match", "--format", "json")
    assert matched.exit_code == 0
    body = json.loads(matched.output)
    assert [(f["advisory_id"], f["fixed_version"], f["provenance"]) for f in body["findings"]] == [
        ("CVE-2026-109618", "8.3.36", "operator_advisory")
    ]
    assert body["complete"] is True

    assert _run("remove", "CVE-2026-109618").exit_code == 0
    assert json.loads(_run("list", "--format", "json").output)["advisories"] == []


def test_match_explicit_report_file_fixed_version_is_clean(state: Path) -> None:
    _run("add", "--file", str(FIXTURE))
    report = state / "fixed.json"
    report.write_text(json.dumps(_report("8.3.36")))
    body = json.loads(_run("match", "--report", str(report), "--format", "json").output)
    assert body["findings"] == []
    assert body["complete"] is True


def test_match_without_stored_inventory_fails_closed(state: Path) -> None:
    _run("add", "--file", str(FIXTURE))
    result = _run("match", "--format", "json")
    assert result.exit_code == 2
    assert json.loads(result.output)["complete"] is False


def test_invalid_advisory_file_is_rejected(state: Path) -> None:
    bad = state / "bad.json"
    bad.write_text(json.dumps({"id": "CVE-2026-1", "summary": "x", "severity": "nope", "affected": []}))
    result = _run("add", "--file", str(bad))
    assert result.exit_code != 0
    assert json.loads(_run("list", "--format", "json").output)["advisories"] == []


def test_mcp_intel_lookup_surfaces_operator_advisory_and_matches(state: Path) -> None:
    from agent_bom.mcp_tools.intel import intel_lookup_impl

    _run("add", "--file", str(FIXTURE))
    history.save_report(_report("8.3.30"))
    body = json.loads(asyncio.run(intel_lookup_impl(advisory_id="CVE-2026-109618")))
    operator = body["operator_advisory"]
    assert operator["advisory"]["id"] == "CVE-2026-109618"
    assert operator["provenance"] == "operator_advisory"
    assert [f["fixed_version"] for f in operator["matches"]["findings"]] == ["8.3.36"]
