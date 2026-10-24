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
    return result.stdout.splitlines()


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
        json.dumps({"mcpServers": {"runner-home-server": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]}}}),
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
