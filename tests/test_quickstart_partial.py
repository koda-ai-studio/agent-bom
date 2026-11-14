"""Quickstart --run on a scan that persisted its graph but exited 1 on a coverage gap."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

GRAPH_URL = "http://127.0.0.1:8422/security-graph?lens=lineage&scan=partial-scan-id"


def _partial_scan(monkeypatch, *, returncode: int = 1, outcome: str = "partial", stale_days: int | None = 87):
    verified: list[dict] = []
    persisted: list[dict] = []

    def fake_run(args, check=False, **kwargs):  # noqa: ANN001, ANN003
        report = Path(args[args.index("-o") + 1])
        report.parent.mkdir(parents=True, exist_ok=True)
        payload: dict = {
            "scan_id": "partial-scan-id",
            "scan_run": {
                "outcome": outcome,
                "issues": [
                    {
                        "code": "scanner_warning",
                        "message": "Some local advisories are stale. Run `agent-bom db update` to refresh them.",
                        "affects_coverage": True,
                    },
                    {"code": "scan_note", "message": "informational note", "affects_coverage": False},
                ],
            },
        }
        if stale_days is not None:
            payload["vuln_data_freshness"] = {"mode": "local", "age_days": stale_days, "stale": True}
        report.write_text(json.dumps(payload), encoding="utf-8")
        return subprocess.CompletedProcess(args, returncode)

    def fake_verify(**kwargs):  # noqa: ANN003
        verified.append(kwargs)
        return {"scan_id": "partial-scan-id", "nodes": 5, "edges": 4}

    def fake_persist(*args, **kwargs):  # noqa: ANN002, ANN003
        persisted.append(kwargs)

    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: "agent-bom")
    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", fake_run)
    monkeypatch.setattr("agent_bom.cli._quickstart._verify_persisted_graph", fake_verify)
    monkeypatch.setattr("agent_bom.cli._quickstart._persist_completed_scan", fake_persist)
    return verified, persisted


def _serve_and_open(served: dict[str, object], opened: list[str]):
    from agent_bom.cli._server import serve_cmd

    return (
        patch.object(serve_cmd, "callback", lambda **kwargs: served.update(kwargs)),
        patch("agent_bom.cli._ui_handoff.open_browser_when_ready", lambda url, host, port: opened.append(url)),
    )


def test_stale_db_finishes_the_handoff_and_keeps_exit_one(tmp_path, monkeypatch):
    verified, persisted = _partial_scan(monkeypatch)
    sample_dir = tmp_path / "stack"

    result = CliRunner().invoke(main, ["quickstart", "--run", "--sample-dir", str(sample_dir)])

    assert result.exit_code == 1, result.output
    assert "Scan exited with status" not in result.output
    assert verified and verified[0]["allow_partial"] is True
    assert persisted == [{"allow_partial": True}]
    assert "Onboarding complete" not in result.output
    assert "coverage is incomplete" in result.output.lower()
    assert "exit status 1" in result.output.lower()
    assert "87 days old" in result.output
    assert "agent-bom db update" in result.output
    assert "Some local advisories are stale" in result.output
    assert "informational note" not in result.output
    assert f"Security graph: {GRAPH_URL}" in result.output
    assert (sample_dir / "gateway-baseline-policy.json").is_file()
    assert "rerun with --open" in result.output


def test_stale_db_still_honours_open(tmp_path, monkeypatch):
    _partial_scan(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "cp.db"))
    served: dict[str, object] = {}
    opened: list[str] = []
    serve_patch, open_patch = _serve_and_open(served, opened)
    with serve_patch, open_patch:
        result = CliRunner().invoke(main, ["quickstart", "--run", "--open", "--sample-dir", str(tmp_path / "s")])

    assert result.exit_code == 1, result.output
    assert opened == [GRAPH_URL]
    assert served["persist"] == str(tmp_path / "cp.db")
    assert "rerun with --open" not in result.output


def test_partial_without_stale_db_omits_the_age(tmp_path, monkeypatch):
    _partial_scan(monkeypatch, stale_days=None)

    result = CliRunner().invoke(main, ["quickstart", "--run", "--sample-dir", str(tmp_path / "stack")])

    assert result.exit_code == 1, result.output
    assert "days old" not in result.output
    assert "Security graph:" in result.output


@pytest.mark.parametrize(("returncode", "outcome"), [(1, "complete"), (1, "failed"), (2, "partial"), (3, "partial")])
def test_non_coverage_exits_still_stop_onboarding(tmp_path, monkeypatch, returncode, outcome):
    verified, _ = _partial_scan(monkeypatch, returncode=returncode, outcome=outcome)

    result = CliRunner().invoke(main, ["quickstart", "--run", "--sample-dir", str(tmp_path / "stack")])

    assert result.exit_code != 0
    assert f"Scan exited with status {returncode}" in result.output
    assert verified == []
    assert "Security graph:" not in result.output


def test_malformed_report_cannot_authorize_a_partial_handoff(tmp_path, monkeypatch):
    verified, _ = _partial_scan(monkeypatch)
    real_run = __import__("agent_bom.cli._quickstart", fromlist=["subprocess"]).subprocess.run

    def broken_report(args, check=False, **kwargs):  # noqa: ANN001, ANN003
        result = real_run(args, check=check, **kwargs)
        Path(args[args.index("-o") + 1]).write_text("{not json", encoding="utf-8")
        return result

    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", broken_report)
    result = CliRunner().invoke(main, ["quickstart", "--run", "--sample-dir", str(tmp_path / "stack")])

    assert result.exit_code != 0
    assert "Scan exited with status 1" in result.output
    assert verified == []


def test_open_complete_run_does_not_tell_the_user_to_rerun_with_open(tmp_path, monkeypatch):
    _partial_scan(monkeypatch, returncode=0, outcome="complete", stale_days=None)
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "cp.db"))
    served: dict[str, object] = {}
    opened: list[str] = []
    serve_patch, open_patch = _serve_and_open(served, opened)
    with serve_patch, open_patch:
        result = CliRunner().invoke(main, ["quickstart", "--run", "--offline", "--open", "--sample-dir", str(tmp_path / "s")])

    assert result.exit_code == 0, result.output
    assert "Onboarding complete" in result.output
    assert "rerun with --open" not in result.output
    assert opened == [GRAPH_URL]
