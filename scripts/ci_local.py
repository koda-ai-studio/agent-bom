#!/usr/bin/env python3
"""Run the gating CI jobs locally, step for step, from .github/workflows/ci.yml.

`make ci-local` runs every ``run:`` step of the gating jobs exactly as CI writes
it, with each job's own dependency install into a private per-job environment
(so test shards run without the cloud extras, like CI). Steps that need GitHub
itself (secrets, the runner, binary downloads) are skipped with a printed
reason; tests/test_ci_local_parity.py fails if a step is ever dropped silently.
Node comes from ``CI_LOCAL_NODE_BIN`` or a Homebrew node@22/@24 (CI pins 22).

    python scripts/ci_local.py                  # lint, security, version-check, ui (when ui/ changed), 4 test shards
    python scripts/ci_local.py --jobs lint,test-smoke   # the pre-push smoke tier
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GATING_JOBS = ("lint", "security", "version-check", "ui", "test-shard")
SMOKE_JOBS = ("lint", "version-check", "test-smoke")

# (pattern, reason). Only steps that cannot run on a workstation belong here.
SKIP_RULES: tuple[tuple[str, str], ...] = (
    (r"No Python, generated contract, or dependency path changed", "documentation-only notice"),
    (r"curl -fsSL", "downloads a pinned scanner binary on the runner"),
    (r"snow app bundle", "needs the Snowflake CLI download"),
    (r"uvicorn agent_bom\.api\.server:app", "binds CI's fixed port 8422; covered by the OpenAPI drift gate"),
    (r"smoke-dev-startup\.mjs", "starts a dev server on a fixed port"),
)

_EXPR = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
_MAPFILE = re.compile(r"mapfile -t (\w+) (<<<|<) (.+)")


@dataclass
class Step:
    job: str
    name: str
    command: str
    action: str
    reason: str = ""
    matrix: str = ""


def matrix_values(job: dict) -> list[str]:
    values = ((job.get("strategy") or {}).get("matrix") or {}).get("shard")
    if isinstance(values, str):
        if "fromJSON(needs.changes.outputs.affected_shards" not in values:
            raise ValueError("unsupported dynamic shard matrix")
        base = _git("merge-base", "origin/main", "HEAD") or "origin/main"
        changed = _git("diff", "--name-only", f"{base}...HEAD").splitlines()
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/pytest_ci_affected.py"), "--include-smoke", "--matrix", *changed],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        values = json.loads(result.stdout)
        if not isinstance(values, list) or not 1 <= len(values) <= 12 or values != list(range(len(values))):
            raise ValueError("affected planner returned invalid shard indices")
    return [str(value) for value in values] if values else [""]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False).stdout.strip()


def _expressions(matrix: str, total: int) -> dict[str, str]:
    base = _git("merge-base", "origin/main", "HEAD") or "origin/main"
    return {
        "matrix.shard": matrix,
        "strategy.job-total": str(total),
        "github.event_name": "pull_request",
        "github.event.pull_request.base.sha": base,
        "github.event.pull_request.head.sha": _git("rev-parse", "HEAD"),
        "github.event.before": base,
        "github.sha": _git("rev-parse", "HEAD"),
        "github.base_ref": "main",
        "github.workspace": str(ROOT),
    }


def _render(command: str, matrix: str, total: int) -> tuple[str, str]:
    known = _expressions(matrix, total)
    unknown = sorted({expr for expr in _EXPR.findall(command) if expr not in known})
    if unknown:
        return command, f"needs GitHub context: {', '.join(unknown)}"
    rendered = _EXPR.sub(lambda match: known[match.group(1)], command)
    # macOS ships bash 3.2, which has no mapfile.
    rendered = _MAPFILE.sub(
        lambda m: f'{m.group(1)}=(); while IFS= read -r _l; do {m.group(1)}+=("$_l"); done {m.group(2)} {m.group(3)}', rendered
    )
    return rendered, ""


def plan(workflow: dict, jobs: tuple[str, ...] = GATING_JOBS) -> list[Step]:
    steps: list[Step] = []
    for job_name in jobs:
        job = workflow["jobs"][job_name]
        matrices = matrix_values(job)
        for matrix in matrices:
            for step in job["steps"]:
                if "run" not in step:
                    continue
                name = str(step.get("name") or step["run"].splitlines()[0])
                command, reason = _render(step["run"], matrix, len(matrices))
                reason = reason or next((why for pattern, why in SKIP_RULES if re.search(pattern, command)), "")
                steps.append(Step(job_name, name, command, "skip" if reason else "run", reason, matrix))
    return steps


def _ui_changed() -> bool:
    return any(path.startswith("ui/") for path in _git("diff", "--name-only", "origin/main...HEAD").splitlines())


# CI pins Node with actions/setup-node; the UI refuses runtimes outside its engines range.
NODE_BIN_CANDIDATES = ("/opt/homebrew/opt/node@22/bin", "/usr/local/opt/node@22/bin", "/opt/homebrew/opt/node@24/bin")


def _node_bin() -> str:
    preferred = os.environ.get("CI_LOCAL_NODE_BIN", "")
    return next((path for path in (preferred, *NODE_BIN_CANDIDATES) if path and Path(path, "node").exists()), "")


def _environment(job: str) -> dict[str, str]:
    venv = ROOT / ".ci-local" / job
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT"))}
    node = _node_bin()
    env.update(
        UV_PROJECT_ENVIRONMENT=str(venv),
        PATH=":".join(part for part in (str(venv / "bin"), node, env.get("PATH", "")) if part),
        ARCHITECTURE_BASE="origin/main",
        BASE_SHA=_git("merge-base", "origin/main", "HEAD"),
        WAIVED="false",
        GITHUB_SHA=_git("rev-parse", "HEAD"),
        GITHUB_EVENT_NAME="pull_request",
        GITHUB_BASE_REF="main",
        CI="true",
    )
    return env


def _guard_ui_node_modules() -> None:
    link = ROOT / "ui" / "node_modules"
    if link.is_symlink():
        # npm ci empties node_modules in place; through a symlink that wipes another checkout's install.
        link.unlink()


def run(steps: list[Step]) -> int:
    failures: list[Step] = []
    for step in steps:
        label = f"[{step.job}{'#' + step.matrix if step.matrix else ''}] {step.name}"
        if step.action == "skip":
            print(f"SKIP {label} — {step.reason}")
            continue
        if step.job == "ui":
            _guard_ui_node_modules()
        started = time.monotonic()
        result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", step.command], cwd=ROOT, env=_environment(step.job), check=False)
        verdict = "PASS" if result.returncode == 0 else "FAIL"
        print(f"{verdict} {label} ({time.monotonic() - started:.0f}s)", flush=True)
        if result.returncode:
            failures.append(step)
    print(f"\n{len(steps) - len(failures)} of {len(steps)} steps passed or were skipped for a stated reason")
    for step in failures:
        print(f"  FAILED [{step.job}{'#' + step.matrix if step.matrix else ''}] {step.name}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", default=",".join(GATING_JOBS), help="comma-separated CI job ids")
    parser.add_argument("--list", action="store_true", help="print the plan without running it")
    args = parser.parse_args(argv)
    if shutil.which("bash") is None:
        print("bash is required", file=sys.stderr)
        return 2
    jobs = tuple(job for job in args.jobs.split(",") if job and (job != "ui" or _ui_changed()))
    steps = plan(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text()), jobs)
    if args.list:
        for step in steps:
            where = f"{step.job}#{step.matrix}" if step.matrix else step.job
            why = f" — {step.reason}" if step.reason else ""
            print(f"{step.action.upper():4} [{where}] {step.name}{why}")
        return 0
    return run(steps)


if __name__ == "__main__":
    raise SystemExit(main())
