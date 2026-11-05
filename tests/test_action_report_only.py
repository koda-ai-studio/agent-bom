"""``severity-threshold: ''`` is report-only, and the Action's Python survives Windows consoles."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_github_action_args import ACTION, ROOT, SCAN_STEP, _env_for, action_args

ARROW_TITLE = "AI agent can reach a credential: project:head → remote-bridge → KEY…"
_PYTHON = Path(sys.executable).parent


def _run_step(tmp_path: Path, inputs: dict[str, str], result: dict | None, exit_code: int) -> tuple[int, dict[str, str], str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "agent-bom"
    payload = "" if result is None else json.dumps(result).replace("'", "'\\''")
    write = "" if result is None else f"printf '%s' '{payload}' > \"$out\"\n"
    stub.write_text(
        '#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$PWD/args.txt"\n'
        'while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done\n'
        f"{write}exit {exit_code}\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    outputs = tmp_path / "outputs"
    env = {
        **_env_for(inputs),
        "PATH": f"{bin_dir}{os.pathsep}{_PYTHON}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(outputs),
        "GITHUB_ACTION_PATH": str(ROOT),
    }
    env.pop("GITHUB_STEP_SUMMARY", None)
    done = subprocess.run(["bash", "-eo", "pipefail", "-c", SCAN_STEP["run"]], cwd=tmp_path, env=env, capture_output=True, text=True)
    values = dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines() if "=" in line)
    return done.returncode, values, done.stdout


def _report(outcome: str = "complete", *, malicious: bool = False) -> dict:
    return {
        "scan_run": {"outcome": outcome},
        "findings": [{"severity": "high", "is_malicious": malicious, "finding_type": "CVE"}],
        "blast_radius": [],
    }


_REPORT_ONLY = {"scan-ref": ".", "format": "json", "severity-threshold": ""}


def test_empty_threshold_asks_the_scan_for_a_report_only_run() -> None:
    args = action_args(severity_threshold="")
    assert "--exit-zero" in args
    assert "--fail-on-severity" not in args


def test_a_set_threshold_keeps_the_gate() -> None:
    args = action_args(severity_threshold="high")
    assert "--exit-zero" not in args
    assert args[args.index("--fail-on-severity") + 1] == "high"


@pytest.mark.parametrize("scan_type", ["image", "fs", "sbom", "iac"])
def test_focused_commands_do_not_receive_a_flag_they_reject(scan_type: str) -> None:
    args = action_args(scan_type=scan_type, scan_ref="target", severity_threshold="")
    assert "--exit-zero" not in args


def test_report_only_passes_on_findings_and_says_so(tmp_path: Path) -> None:
    code, outputs, _ = _run_step(tmp_path, {**_REPORT_ONLY, "scan-type": "fs"}, _report(), 1)
    assert code == 0
    assert outputs["exit_code"] == "1"
    assert outputs["gate_exit_code"] == "0"
    assert outputs["scan_status"] == "violations"


def test_report_only_with_findings_is_not_called_clean(tmp_path: Path) -> None:
    code, outputs, _ = _run_step(tmp_path, _REPORT_ONLY, _report(), 0)
    assert code == 0
    assert outputs["scan_status"] == "violations"


def test_report_only_keeps_a_partial_baseline_usable_but_visible(tmp_path: Path) -> None:
    code, outputs, stdout = _run_step(tmp_path, _REPORT_ONLY, _report("partial"), 1)
    assert code == 0
    assert outputs["exit_code"] == "1"
    assert outputs["scan_status"] == "partial"
    assert "::warning" in stdout and "partial" in stdout


def test_report_only_reads_partial_from_sarif_too(tmp_path: Path) -> None:
    sarif = {"runs": [{"properties": {"scan_outcome": "partial"}, "results": []}]}
    code, outputs, _ = _run_step(tmp_path, {"scan-ref": ".", "severity-threshold": ""}, sarif, 1)
    assert code == 0
    assert outputs["scan_status"] == "partial"


@pytest.mark.parametrize(
    ("label", "inputs", "result", "exit_code", "expected"),
    [
        ("malicious package", {}, _report(malicious=True), 1, 1),
        ("failed scan", {}, _report("failed"), 1, 1),
        ("no report written", {}, None, 1, 1),
        ("report without an outcome", {}, {"findings": [], "blast_radius": []}, 1, 1),
        ("usage error", {}, _report(), 2, 2),
        ("freshness gate", {}, _report(), 3, 3),
        ("explicit policy gate", {"policy": "policy.yml"}, _report(), 1, 1),
        ("explicit KEV gate", {"fail-on-kev": "true"}, _report(), 1, 1),
    ],
)
def test_report_only_never_hides_what_is_not_a_severity_verdict(
    tmp_path: Path, label: str, inputs: dict[str, str], result: dict | None, exit_code: int, expected: int
) -> None:
    code, _, _ = _run_step(tmp_path, {**_REPORT_ONLY, **inputs}, result, exit_code)
    assert code == expected, label


@pytest.mark.parametrize("outcome", ["complete", "partial"])
def test_a_real_gate_still_fails_closed(tmp_path: Path, outcome: str) -> None:
    code, outputs, _ = _run_step(tmp_path, {"scan-ref": ".", "format": "json", "severity-threshold": "high"}, _report(outcome), 1)
    assert code == 1
    assert outputs["gate_exit_code"] == "1"


def test_commands_with_their_own_gate_keep_it(tmp_path: Path) -> None:
    code, _, _ = _run_step(tmp_path, {**_REPORT_ONLY, "scan-type": "secrets"}, {"findings": [{"severity": "high"}], "total": 1}, 1)
    assert code == 1


def test_pr_comment_reports_the_step_verdict() -> None:
    step = next(step for step in ACTION["runs"]["steps"] if step.get("name") == "Post PR comment with findings summary")
    assert step["env"]["EXIT_CODE"] == "${{ steps.scan.outputs.gate_exit_code }}"


def test_summary_names_partial_coverage(tmp_path: Path) -> None:
    result = tmp_path / "report.json"
    result.write_text(json.dumps(_report("partial")), encoding="utf-8")
    out = _script("action_report.py", "summary", str(result), "--exit-code", "0")
    assert out.returncode == 0
    assert "Partial scan" in out.stdout.decode("utf-8")


# ── Windows consoles ────────────────────────────────────────────────────────


def _script(name: str, *args: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    full_env = {**os.environ, "PYTHONIOENCODING": "cp1252", **(env or {})}
    full_env.pop("PYTHONUTF8", None)
    return subprocess.run([sys.executable, str(ROOT / "scripts" / name), *args], capture_output=True, env=full_env, cwd=cwd)


def _sarif_with_arrow(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "R", "properties": {"security-severity": "9.5"}}]}},
                        "properties": {"scan_outcome": "complete"},
                        "results": [
                            {
                                "ruleId": "R",
                                "level": "error",
                                "message": {"text": ARROW_TITLE},
                                "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".cursor/mcp.json"}}}],
                                "properties": {"remediation_guidance": "Rotate → then remove"},
                            }
                        ],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("mode", ["summary", "comment"])
def test_report_renders_under_cp1252(tmp_path: Path, mode: str) -> None:
    done = _script("action_report.py", mode, str(_sarif_with_arrow(tmp_path / "r.sarif")), "--exit-code", "1")
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    text = done.stdout.decode("utf-8")
    assert "project:head → remote-bridge" in text
    assert "Rotate → then remove" in text


def test_annotations_emit_under_cp1252(tmp_path: Path) -> None:
    done = _script("emit_github_annotations.py", str(_sarif_with_arrow(tmp_path / "r.sarif")))
    assert done.returncode == 0
    assert b"annotation emission failed" not in done.stderr
    assert "project:head → remote-bridge" in done.stdout.decode("utf-8")


def test_metrics_read_utf8_under_cp1252(tmp_path: Path) -> None:
    sarif = _sarif_with_arrow(tmp_path / "r.sarif")
    done = _script("action_result_metrics.py", env={"RESULT_FILE": str(sarif), "VULN_COUNT": "1"})
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    assert b"blast_radius_critical_count=1" in done.stdout


def test_sarif_checker_prints_under_cp1252(tmp_path: Path) -> None:
    sarif = tmp_path / "r.sarif"
    sarif.write_text(
        json.dumps({"runs": [{"results": [{"ruleId": "→", "message": {"text": "→"}, "locations": []}]}]}, ensure_ascii=False),
        encoding="utf-8",
    )
    done = _script("check_sarif_locations.py", str(sarif))
    assert done.returncode == 1
    assert "→: no locations" in done.stdout.decode("utf-8")


def test_mcp_gate_prints_under_cp1252(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    git = ["git", "-C", str(tmp_path), "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8")
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "a"], check=True)
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"pont→serveur": {"command": "npx", "args": ["-y", "x"]}}}), encoding="utf-8"
    )
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "b"], check=True)
    done = _script("action_mcp_gate.py", "--base", "HEAD~1", "--head", "HEAD", "--offline", cwd=tmp_path)
    assert b"UnicodeEncodeError" not in done.stderr, done.stderr.decode("utf-8", "replace")
    assert "pont→serveur" in done.stdout.decode("utf-8")


def test_inline_python_opens_results_as_utf8() -> None:
    run = SCAN_STEP["run"]
    assert "json.load(open(os.environ['RESULT_FILE']))" not in run
    assert "json.load(open(os.environ['SARIF_FILE']))" not in run


def test_every_python_step_runs_in_utf8_mode() -> None:
    for step in ACTION["runs"]["steps"]:
        if "python3" in str(step.get("run", "")):
            assert step.get("env", {}).get("PYTHONUTF8") == "1", step["name"]
