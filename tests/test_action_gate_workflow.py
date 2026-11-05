"""The release check for the documented pull request gate stays real, fast and quiet."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "action-gate-e2e.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _action_steps() -> list[dict]:
    return [step for step in _workflow()["jobs"]["gate"]["steps"] if step.get("uses") == "./"]


def test_runs_on_linux_and_windows_with_least_privilege() -> None:
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["gate"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-latest", "windows-latest"}
    assert job["strategy"]["fail-fast"] is False
    assert "permissions" not in job


def test_triggers_on_the_code_it_guards_and_on_release() -> None:
    workflow = _workflow()
    on = workflow.get("on") or workflow.get(True)
    assert {
        "action.yml",
        "scripts/action_*.py",
        "scripts/check_sarif_locations.py",
        "scripts/emit_github_annotations.py",
        "src/agent_bom/output/sarif*.py",
        "src/agent_bom/scan_delta.py",
        ".github/workflows/action-gate-e2e.yml",
    } <= set(on["pull_request"]["paths"])
    assert "v*.*.*" in on["push"]["tags"]


def test_every_action_run_is_local_uploads_nothing_and_never_syncs_the_database() -> None:
    steps = _action_steps()
    assert len(steps) == 4
    for step in steps:
        assert step["with"]["auto-update-db"] == "false"
        assert step["with"]["install-from-source"] == "true"
        assert step["with"]["pr-comment"] == "false"
        assert step["with"].get("upload-sarif", "false") == "false"


def test_every_external_action_is_pinned_to_a_sha() -> None:
    for line in WORKFLOW.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*-?\s*uses:\s*(\S+)", line)
        if match and match.group(1) != "./":
            assert re.search(r"@[0-9a-f]{40}$", match.group(1)), line


def test_flow_follows_the_documented_shape() -> None:
    by_id = {step.get("id"): step for step in _action_steps()}
    assert by_id["baseline"]["with"]["severity-threshold"] == ""
    assert by_id["baseline"]["with"]["format"] == "json"
    assert by_id["gate-identical"]["with"]["baseline"] == "baseline.json"
    assert by_id["gate-identical"]["with"]["scan-ref"] == "head"
    assert "continue-on-error" not in by_id["gate-identical"]
    assert by_id["gate-vulnerable"]["continue-on-error"] is True


def test_assertions_cover_verdicts_and_sarif_structure() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'test "$VULNERABLE_OUTCOME" = "failure"' in text
    assert "check_sarif_locations.py full.sarif --require-results" in text
    assert "check_sarif_locations.py gate-identical.sarif --require-empty" in text
    assert "check_sarif_locations.py gate-vulnerable.sarif --only-package urllib3" in text


def test_the_fixture_is_generated_not_committed() -> None:
    assert not (ROOT / "base").exists()
    assert not (ROOT / "head").exists()


def test_documented_flow_matches_the_action_it_runs() -> None:
    docs = (ROOT / "site-docs" / "integrations" / "github-action.md").read_text(encoding="utf-8")
    assert "severity-threshold: ''" in docs
    assert "scan-ref: head" in docs
    assert "baseline: baseline.json" in docs
