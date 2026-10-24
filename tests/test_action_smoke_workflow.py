"""The Action smoke workflow runs every scan-type on pull requests that touch it."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "action-smoke.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _scan_types_in_dispatch() -> set[str]:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    script = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")["run"]
    message = re.search(r"Unknown scan-type: \$INPUT_SCAN_TYPE\. Use: ([a-z, ]+)", script)
    assert message
    return {name.strip() for name in message.group(1).split(",")}


def test_smoke_matrix_covers_every_scan_type() -> None:
    job = _workflow()["jobs"]["smoke"]
    covered = {entry["scan-type"] for entry in job["strategy"]["matrix"]["include"]}
    assert covered == _scan_types_in_dispatch()
    assert job["strategy"]["fail-fast"] is False


def test_smoke_runs_on_action_changes_only_and_stays_fast() -> None:
    workflow = _workflow()
    on = workflow.get("on") or workflow.get(True)
    paths = set(on["pull_request"]["paths"])
    assert {"action.yml", "scripts/action_*.py", "scripts/emit_github_annotations.py", ".github/workflows/action-smoke.yml"} <= paths
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["smoke"]
    assert job["timeout-minutes"] <= 10


def test_smoke_never_syncs_the_database_and_rejects_usage_errors() -> None:
    job = _workflow()["jobs"]["smoke"]
    action_step = next(step for step in job["steps"] if step.get("uses") == "./")
    assert action_step["with"]["auto-update-db"] == "false"
    assert action_step["with"]["install-from-source"] == "true"
    assert action_step["with"]["scan-type"] == "${{ matrix.scan-type }}"
    verify = next(step for step in job["steps"] if step.get("name") == "Verify the scan ran")
    assert "usage_error" in verify["run"] and "exit 1" in verify["run"]
