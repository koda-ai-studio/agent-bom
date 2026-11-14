"""``scan --log-json`` writes only JSON lines to stderr and ``-q`` silences progress."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "ordinary-python-app"


def _run_scan(tmp_path: Path, *flags: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_BOM_")}
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "AGENT_BOM_STATE_DIR": str(tmp_path / "state"),
            "PYTHONPATH": str(ROOT / "src"),
            "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
            "AGENT_BOM_OFFLINE": "1",
            "NO_COLOR": "1",
        }
    )
    report = tmp_path / "r.json"
    proc = subprocess.run(
        [sys.executable, "-m", "agent_bom", "scan", str(FIXTURE), *flags, "-f", "json", "-o", str(report)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=240,
    )
    return proc, report


def _json_lines(stderr: str) -> list[dict]:
    events = []
    for line in stderr.splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pytest.fail(f"stderr line is not JSON: {line!r}\n--- stderr ---\n{stderr[-3000:]}")
    return events


def test_log_json_quiet_scan_writes_only_json_to_stderr_and_nothing_to_stdout(tmp_path: Path) -> None:
    proc, report = _run_scan(tmp_path, "--log-json", "-q")

    assert proc.stdout == ""
    events = _json_lines(proc.stderr)
    assert all(event["level"] in {"WARNING", "ERROR", "CRITICAL"} for event in events), events
    assert "packages" in json.loads(report.read_text()) or json.loads(report.read_text())


def test_log_json_scan_emits_progress_as_structured_records(tmp_path: Path) -> None:
    proc, report = _run_scan(tmp_path, "--log-json")

    assert proc.stdout == ""
    events = _json_lines(proc.stderr)
    progress = [event for event in events if event["logger"] == "agent_bom.progress"]
    assert progress, proc.stderr[-2000:]
    assert any("Discovering MCP configurations" in event["msg"] for event in progress)
    assert all(event["level"] == "INFO" and event["msg"].strip() for event in progress)
    assert not any("[bold" in event["msg"] or "\x1b[" in event["msg"] for event in progress)
    assert report.exists()


def test_quiet_scan_prints_no_discovery_banner(tmp_path: Path) -> None:
    proc, report = _run_scan(tmp_path, "-q")

    # -q keeps the result block on stdout but drops progress and banners.
    assert proc.stdout.startswith("agent-bom: ")
    assert "Discovering" not in proc.stdout + proc.stderr
    assert "MCP configurations" not in proc.stdout + proc.stderr
    assert report.exists()


def test_progress_stream_keeps_rule_titles_and_drops_bare_rules(caplog) -> None:
    import logging

    from agent_bom.core.progress_log import PROGRESS_LOGGER, progress_log_console

    con = progress_log_console()
    with caplog.at_level(logging.INFO, logger=PROGRESS_LOGGER):
        con.rule("Discovery")
        con.rule()
        con.print("  [green]done[/green] partial", end="")
        con.file.flush()

    assert [record.getMessage() for record in caplog.records] == ["Discovery", "done partial"]
