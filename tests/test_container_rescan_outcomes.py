"""Image issue automation must separate actionable findings from missing evidence."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _report(outcome="complete", results=None):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "agent-bom"}},
                "results": results or [],
                "properties": {"scan_outcome": outcome},
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }


def _issue_action(tmp_path, report, table="failure", sarif="failure"):
    """Execute the real workflow decision with a local gh recorder, never GitHub."""
    report_path = tmp_path / "image-scan-container-amd64.sarif"
    if report is not None:
        report_path.write_text(json.dumps(report))
        (tmp_path / ("original-" + report_path.name)).write_text(json.dumps(report))
    trace = tmp_path / "gh.jsonl"
    mock = tmp_path / "gh"
    mock.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        "with open(os.environ['GH_TRACE'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
        "if sys.argv[1:3] == ['issue', 'list']: print('6031')\n"
    )
    mock.chmod(0o700)
    output = tmp_path / "outputs"
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "GH_TRACE": str(trace),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_SERVER_URL": "https://example.invalid",
        "GITHUB_REPOSITORY": "fixture/repo",
        "GITHUB_RUN_ID": "1",
        "IMAGE_ID": "sha256:" + "a" * 64,
    }
    values = {
        "matrix.platform": "linux/amd64",
        "matrix.sarif_category": "container-amd64",
        "steps.image_scan_table.outcome": table,
        "steps.image_scan_sarif.outcome": sarif,
    }
    steps = yaml.safe_load((ROOT / ".github/workflows/container-rescan.yml").read_text())["jobs"]["rescan"]["steps"]
    for step in steps:
        if step.get("name") not in {"Classify container scan evidence", "Open or close base image vulnerability issue"}:
            continue
        command = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda m: values[m[1]], step["run"])
        command = command.replace("scripts/", str(ROOT / "scripts") + "/")
        subprocess.run(["bash", "-c", command], cwd=tmp_path, env=env, capture_output=True, text=True, check=True)
        if output.exists():
            for line in output.read_text().splitlines():
                key, value = line.split("=", 1)
                values[f"steps.triage.outputs.{key}"] = value
    return [args for line in trace.read_text().splitlines() if (args := json.loads(line))[:1] == ["issue"] and args[1] != "list"]


def test_partial_zero_finding_scan_is_not_called_actionable(tmp_path):
    actions = _issue_action(tmp_path, _report("partial"))
    assert len(actions) == 1 and actions[0][:2] == ["issue", "comment"]
    assert "inconclusive" in " ".join(actions[0]).lower()
    assert "Automated Base Image Vulnerability Alert" not in " ".join(actions[0])


@pytest.mark.parametrize("report", [None, {}, {"runs": []}, _report("partial")])
def test_missing_or_incomplete_evidence_never_closes_an_issue(tmp_path, report):
    actions = _issue_action(tmp_path, report, table="success", sarif="success")
    assert all(action[:2] != ["issue", "close"] for action in actions)


def test_complete_success_closes_with_image_receipt(tmp_path):
    actions = _issue_action(tmp_path, _report(), table="success", sarif="success")
    assert actions[0][:3] == ["issue", "close", "6031"]
    assert "sha256:" in " ".join(actions[0])


def test_fixable_medium_finding_is_actionable_even_with_partial_coverage(tmp_path):
    finding = {"ruleId": "CVE-2099-0001", "level": "warning", "properties": {"fixed_version": "2.0"}}
    actions = _issue_action(tmp_path, _report("partial", [finding]))
    assert "Automated Base Image Vulnerability Alert" in " ".join(actions[0])


@pytest.mark.parametrize("change", ["failed_invocation", "coverage_warning", "missing_invocation", "wrong_tool", "malformed_results"])
def test_incomplete_report_cannot_close_even_when_steps_succeed(tmp_path, change):
    report = _report()
    run = report["runs"][0]
    if change == "failed_invocation":
        run["invocations"][0]["executionSuccessful"] = False
    elif change == "coverage_warning":
        run["invocations"][0]["toolExecutionNotifications"] = [{"properties": {"affectsCoverage": True}}]
    elif change == "missing_invocation":
        del run["invocations"]
    elif change == "wrong_tool":
        run["tool"]["driver"]["name"] = "other"
    else:
        run["results"] = None
    assert all(action[:2] != ["issue", "close"] for action in _issue_action(tmp_path, report, "success", "success"))


@pytest.mark.parametrize("level,fixed", [("note", "2.0"), ("warning", ""), ("error", None)])
def test_non_actionable_results_do_not_open_vulnerability_alert(tmp_path, level, fixed):
    finding = {"level": level, "properties": {"fixed_version": fixed}}
    actions = _issue_action(tmp_path, _report(results=[finding]), "success", "success")
    assert actions[0][:2] == ["issue", "close"]
