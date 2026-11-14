"""Under ``--log-json`` a scan's verdict and exit reason are one record each, at an honest level."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _scan(tmp_path: Path, *flags: str) -> tuple[subprocess.CompletedProcess[str], list[dict], Path]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_BOM_")}
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "AGENT_BOM_STATE_DIR": str(tmp_path / "state"),
            "PYTHONPATH": str(ROOT / "src"),
            "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
            "NO_COLOR": "1",
        }
    )
    report = tmp_path / "report.json"
    proc = subprocess.run(
        [sys.executable, "-m", "agent_bom", "scan", "--demo", "--offline", "--no-auto-update-db", *flags, "-f", "json", "-o", str(report)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=240,
    )
    events = [json.loads(line) for line in proc.stderr.splitlines() if line.strip()]
    return proc, events, report


def _verdicts(events: list[dict]) -> list[dict]:
    return [event for event in events if event["logger"] == "agent_bom.verdict"]


def test_quiet_fail_is_one_warning_verdict_record(tmp_path: Path) -> None:
    proc, events, report = _scan(tmp_path, "--log-json", "-q")

    assert proc.returncode == 1, proc.stderr[-2000:]
    assert proc.stdout == ""
    verdicts = _verdicts(events)
    assert len(verdicts) == 1, events
    verdict = verdicts[0]
    assert verdict["level"] == "WARNING"
    assert verdict["msg"].startswith("agent-bom: FAIL")
    context = verdict["context"]
    assert context["verdict"] == "FAIL"
    assert context["exit_code"] == 1
    assert context["reasons"] and all(isinstance(reason, str) and reason for reason in context["reasons"])
    assert context["report"] == str(report)
    assert context["outcome"] == "complete"
    assert sum(context["counts"].values()) == context["findings"] > 0
    assert context["packages"] > 0
    assert not any(event["level"] == "ERROR" for event in events), events


def test_quiet_pass_is_one_info_verdict_record(tmp_path: Path) -> None:
    proc, events, report = _scan(tmp_path, "--log-json", "-q", "--no-scan", "--exit-zero")

    assert proc.returncode == 0, proc.stderr[-2000:]
    verdicts = _verdicts(events)
    assert len(verdicts) == 1, events
    assert verdicts[0]["level"] == "INFO"
    assert verdicts[0]["context"]["verdict"] == "PASS"
    assert verdicts[0]["context"]["exit_code"] == 0
    assert verdicts[0]["context"]["reasons"] == []
    assert verdicts[0]["context"]["report"] == str(report)
    assert not any(event["level"] == "ERROR" for event in events), events


def test_exit_reason_without_quiet_is_one_warning_record(tmp_path: Path) -> None:
    proc, events, _ = _scan(tmp_path, "--log-json")

    assert proc.returncode == 1, proc.stderr[-2000:]
    reasons = [event for event in events if "Exiting with code 1" in event["msg"]]
    assert len(reasons) == 1, [event["msg"] for event in events][-12:]
    reason = reasons[0]
    assert reason["level"] == "WARNING"
    assert reason["msg"].startswith("Exiting with code 1: ") and len(reason["msg"]) > len("Exiting with code 1: ")
    assert reason["context"]["exit_code"] == 1
    assert reason["context"]["reason"] in reason["msg"]
    assert not any(event["msg"].strip() == "Exiting with code 1:" for event in events)
