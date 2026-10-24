"""Executable contract for the argument list ``action.yml`` hands to the CLI.

The scan step's shell is run for real (up to the CLI invocation) with the same
``INPUT_*`` environment GitHub would build from the action inputs, so these
tests assert the arguments the Action would actually execute.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import click
import pytest
import yaml

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
SCAN_STEP = next(step for step in ACTION["runs"]["steps"] if step.get("id") == "scan")
ARG_SCRIPT = SCAN_STEP["run"].split("# Run scan, capture exit code", 1)[0]


def _env_for(inputs: dict[str, str]) -> dict[str, str]:
    unknown = set(inputs) - set(ACTION["inputs"])
    assert not unknown, f"not an action input: {unknown}"
    env = {key: value for key, value in os.environ.items() if not key.startswith("INPUT_")}
    for name, expression in SCAN_STEP["env"].items():
        if not name.startswith("INPUT_"):
            continue
        input_name = expression.removeprefix("${{ inputs.").removesuffix(" }}")
        env[name] = str(inputs.get(input_name, ACTION["inputs"][input_name].get("default", "")))
    return env


def run_arg_script(inputs: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", ARG_SCRIPT + '\nprintf "%s\\n" "${ARGS[@]}"'],
        env=_env_for(inputs),
        capture_output=True,
        text=True,
        check=False,
    )


def action_args(**inputs: str) -> list[str]:
    result = run_arg_script({key.replace("_", "-"): value for key, value in inputs.items()})
    assert result.returncode == 0, result.stdout + result.stderr
    return _args_only(result.stdout)


def _args_only(stdout: str) -> list[str]:
    return [line for line in stdout.splitlines() if not line.startswith("::")]


# ── P0: default scope covers the checkout ───────────────────────────────────


def test_default_scan_is_scoped_to_the_checkout() -> None:
    args = action_args()
    assert args[:2] == ["scan", "."]


def test_scan_ref_sets_the_scan_scope() -> None:
    args = action_args(scan_ref="services/api")
    assert args[:2] == ["scan", "services/api"]


def test_explicit_artifact_without_scope_skips_ambient_discovery() -> None:
    args = action_args(sbom="tests/fixtures/test-sbom.cdx.json")
    assert args[0] == "scan"
    assert "." not in args
    assert "--no-discover" in args
    assert args[args.index("--sbom") + 1] == "tests/fixtures/test-sbom.cdx.json"


def _write_iac_fixture(repo: Path) -> None:
    (repo / "infra").mkdir(parents=True)
    (repo / "infra" / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n  bucket = "example-data"\n  acl    = "public-read"\n}\n',
        encoding="utf-8",
    )
    (repo / "k8s").mkdir()
    (repo / "k8s" / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n"
        "  selector:\n    matchLabels: {app: web}\n  template:\n    metadata:\n      labels: {app: web}\n"
        "    spec:\n      containers:\n        - name: web\n          image: nginx:latest\n"
        "          securityContext:\n            privileged: true\n",
        encoding="utf-8",
    )


def _write_runner_home(home: Path) -> None:
    cursor = home / ".cursor"
    cursor.mkdir(parents=True)
    (cursor / "mcp.json").write_text(
        json.dumps({"mcpServers": {"runner-home-server": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}),
        encoding="utf-8",
    )


def _run_cli(args: list[str], *, cwd: Path, home: Path) -> dict:
    env = {**os.environ, "HOME": str(home), "AGENT_BOM_NO_TELEMETRY": "1"}
    env.pop("AGENT_BOM_STATE_DIR", None)
    subprocess.run([sys.executable, "-m", "agent_bom", *args, "--offline", "-q"], cwd=cwd, env=env, capture_output=True, text=True)
    return json.loads((cwd / "out.json").read_text(encoding="utf-8"))


def test_default_action_scope_scans_iac_and_ignores_runner_home(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    home = tmp_path / "home"
    _write_iac_fixture(repo)
    _write_runner_home(home)

    args = action_args(auto_update_db="false", format="json", output="out.json")
    report = _run_cli(args, cwd=repo, home=home)

    rules = {finding["rule_id"] for finding in report.get("iac_findings", {}).get("findings", [])}
    assert any(rule.startswith("TF-") for rule in rules), rules
    assert any(rule.startswith("K8S-") for rule in rules), rules
    assert report["agents"] == []

    # Control: the unscoped command the Action used to run picks up the runner
    # home config and misses the nested IaC, so the assertions above are not vacuous.
    bare = _run_cli(["scan", "-f", "json", "-o", "out.json"], cwd=repo, home=home)
    assert not bare.get("iac_findings", {}).get("findings")
    assert any(server["name"] == "runner-home-server" for agent in bare["agents"] for server in agent.get("mcp_servers", []))


# ── P0: every scan-type runs with default inputs ────────────────────────────

SCAN_TYPE_REFS = {
    "scan": "",
    "image": "nginx:1.25",
    "fs": ".",
    "sbom": "tests/fixtures/test-sbom.cdx.json",
    "iac": "infra,k8s",
    "secrets": ".",
    "code": ".",
    "skills": ".",
}


def _cli_command(args: list[str]) -> click.Command:
    ctx = click.Context(main)
    command = main.get_command(ctx, args[0])
    assert command is not None, args[0]
    if isinstance(command, click.Group):
        command = command.get_command(ctx, args[1])
    assert command is not None
    return command


def _accepted_options(command: click.Command) -> set[str]:
    accepted: set[str] = set()
    for param in command.params:
        accepted.update(getattr(param, "opts", []))
        accepted.update(getattr(param, "secondary_opts", []))
    return accepted


def _options(args: list[str]) -> set[str]:
    return {arg for arg in args if arg.startswith("-") and arg != "-"}


@pytest.mark.parametrize("scan_type", sorted(SCAN_TYPE_REFS))
def test_every_scan_type_with_default_inputs_only_passes_accepted_flags(scan_type: str) -> None:
    args = action_args(scan_type=scan_type, scan_ref=SCAN_TYPE_REFS[scan_type])
    rejected = _options(args) - _accepted_options(_cli_command(args))
    assert not rejected, f"{scan_type}: {args}"


GATE_INPUTS = {
    "severity-threshold": "critical",
    "warn-on-severity": "medium",
    "enrich": "true",
    "exclude-unfixable": "true",
    "gpu-scan": "true",
    "skill-only": "true",
    "os-packages": "true",
    "ai-inventory": "src",
    "remediate": "remediation.md",
    "ignore-file": ".agent-bom-ignore.yaml",
}


@pytest.mark.parametrize("scan_type", sorted(SCAN_TYPE_REFS))
def test_optional_inputs_never_reach_a_subcommand_that_rejects_them(scan_type: str) -> None:
    inputs = {"scan-type": scan_type, "scan-ref": SCAN_TYPE_REFS[scan_type], "format": "json", **GATE_INPUTS}
    result = run_arg_script(inputs)
    assert result.returncode == 0, result.stdout + result.stderr
    args = _args_only(result.stdout)
    rejected = _options(args) - _accepted_options(_cli_command(args))
    assert not rejected, f"{scan_type}: {args}"
    if scan_type != "scan":
        assert "::warning::" in result.stdout


def test_focused_scan_types_keep_the_gates_they_support() -> None:
    for scan_type in ("image", "fs", "sbom", "iac"):
        args = action_args(scan_type=scan_type, scan_ref=SCAN_TYPE_REFS[scan_type])
        assert args[args.index("--fail-on-severity") + 1] == "high", scan_type
    assert "--enrich" in action_args(scan_type="fs", enrich="true")
    assert "--exclude-unfixable" in action_args(scan_type="image", scan_ref="nginx:1.25", exclude_unfixable="true")


@pytest.mark.parametrize("scan_type", ["image", "fs", "sbom", "iac", "secrets", "code"])
def test_unenforceable_blocking_gates_fail_closed(scan_type: str) -> None:
    for name, value in (("fail-on-kev", "true"), ("baseline", "baseline.json")):
        result = run_arg_script({"scan-type": scan_type, "scan-ref": SCAN_TYPE_REFS[scan_type], "format": "json", name: value})
        assert result.returncode != 0, (scan_type, name)
        assert "::error::" in result.stdout


@pytest.mark.parametrize("scan_type", ["secrets", "code"])
def test_secrets_and_code_default_inputs_fall_back_to_json(scan_type: str) -> None:
    args = action_args(scan_type=scan_type, scan_ref=".")
    assert args[args.index("-f") + 1] == "json"
    assert args[args.index("-o") + 1] == "agent-bom-results.json"


def test_skills_keeps_its_default_sarif_output() -> None:
    args = action_args(scan_type="skills", scan_ref=".")
    assert args[args.index("-f") + 1] == "sarif"
    assert args[args.index("-o") + 1] == "agent-bom-results.sarif"


# ── P0: baseline input drives the real delta flag ───────────────────────────


def test_baseline_input_passes_the_real_delta_flag() -> None:
    args = action_args(baseline="baseline.json")
    assert args[args.index("--baseline") + 1] == "baseline.json"
    assert "--delta" in args
    rejected = _options(args) - _accepted_options(_cli_command(args))
    assert not rejected, args


def test_baseline_input_runs_against_the_cli(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    home = tmp_path / "home"
    _write_iac_fixture(repo)
    home.mkdir()
    env = {**os.environ, "HOME": str(home)}
    base = subprocess.run(
        [sys.executable, "-m", "agent_bom", "scan", ".", "-f", "json", "-o", "baseline.json", "--offline", "-q"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )
    assert (repo / "baseline.json").is_file(), base.stderr

    args = action_args(auto_update_db="false", baseline="baseline.json", format="json", output="out.json")
    command = [sys.executable, "-m", "agent_bom", *args, "--offline", "-q"]
    result = subprocess.run(command, cwd=repo, env=env, capture_output=True, text=True)
    assert result.returncode != 2, result.stderr
    assert json.loads((repo / "out.json").read_text(encoding="utf-8"))["delta"]["enabled"] is True


# ── SBOM artifact ───────────────────────────────────────────────────────────


def _sbom_command(**inputs: str) -> list[str]:
    result = run_arg_script({key.replace("_", "-"): value for key, value in inputs.items()})
    assert result.returncode == 0, result.stdout
    script = ARG_SCRIPT + '\nprintf "%s\\n" "${SBOM_ARGS[@]}"'
    out = subprocess.run(
        ["bash", "-c", script], env=_env_for({k.replace("_", "-"): v for k, v in inputs.items()}), capture_output=True, text=True
    )
    return [arg for arg in _args_only(out.stdout) if arg]


@pytest.mark.parametrize(("choice", "fmt", "suffix"), [("cyclonedx", "cyclonedx", ".cdx.json"), ("spdx", "spdx", ".spdx.json")])
def test_sbom_artifact_reuses_the_scan_scope_offline(choice: str, fmt: str, suffix: str) -> None:
    command = _sbom_command(sbom_artifact=choice)
    assert command[:2] == ["scan", "."]
    assert command[command.index("-f") + 1] == fmt
    assert command[command.index("-o") + 1] == f"agent-bom-sbom{suffix}"
    assert "--offline" in command
    assert "--fail-on-severity" not in command
    assert not _options(command) - _accepted_options(_cli_command(command))


def test_sbom_artifact_for_an_image_scans_that_image() -> None:
    command = _sbom_command(scan_type="image", scan_ref="nginx:1.25", sbom_artifact="cyclonedx")
    assert command[:2] == ["image", "nginx:1.25"]
    assert not _options(command) - _accepted_options(_cli_command(command))


def test_sbom_artifact_defaults_off_and_rejects_unknown_values() -> None:
    assert ACTION["inputs"]["sbom-artifact"]["default"] == "none"
    assert _sbom_command() == []
    result = run_arg_script({"sbom-artifact": "xml"})
    assert result.returncode != 0 and "::error::" in result.stdout
    result = run_arg_script({"scan-type": "iac", "scan-ref": "infra", "sbom-artifact": "cyclonedx"})
    assert result.returncode != 0


def test_sbom_artifact_is_uploaded() -> None:
    upload = next(step for step in ACTION["runs"]["steps"] if step.get("name") == "Upload SBOM artifact")
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"]["path"] == "${{ steps.scan.outputs.sbom_file }}"
    assert "steps.scan.outputs.sbom_file != ''" in upload["if"]


# ── Status from JSON results ────────────────────────────────────────────────


def _run_scan_step(tmp_path: Path, inputs: dict[str, str], result: dict, exit_code: int) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "agent-bom"
    payload = json.dumps(result).replace("'", "'\\''")
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done\n'
        f"printf '%s' '{payload}' > \"$out\"\nexit {exit_code}\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    outputs = tmp_path / "outputs"
    env = {**_env_for(inputs), "PATH": f"{bin_dir}:{os.environ['PATH']}", "GITHUB_OUTPUT": str(outputs), "GITHUB_ACTION_PATH": str(ROOT)}
    env.pop("GITHUB_STEP_SUMMARY", None)
    subprocess.run(["bash", "-eo", "pipefail", "-c", SCAN_STEP["run"]], cwd=tmp_path, env=env, capture_output=True, text=True)
    return dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines() if "=" in line)


@pytest.mark.parametrize(
    ("scan_type", "result"),
    [
        ("secrets", {"findings": [{"severity": "critical"}], "total": 1}),
        ("scan", {"findings": [{"severity": "high"}, {"severity": "low"}], "blast_radius": []}),
    ],
)
def test_json_results_with_findings_report_violations_not_errors(tmp_path: Path, scan_type: str, result: dict) -> None:
    outputs = _run_scan_step(tmp_path, {"scan-type": scan_type, "scan-ref": ".", "format": "json", "severity-threshold": ""}, result, 1)
    assert outputs["scan_status"] == "violations", outputs
    assert int(outputs["vuln_count"]) == len(result["findings"])
