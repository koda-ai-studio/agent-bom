"""`make ci-local` runs what CI runs: every run step of the gating jobs is either executed or skipped for a stated reason."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _ci_local():
    spec = importlib.util.spec_from_file_location("ci_local", ROOT / "scripts" / "ci_local.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ci_local"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_every_gating_step_is_planned_and_no_step_is_dropped_silently() -> None:
    ci_local = _ci_local()
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    expected = sum(
        len([s for s in workflow["jobs"][job]["steps"] if "run" in s]) * len(ci_local.matrix_values(workflow["jobs"][job]))
        for job in ci_local.GATING_JOBS
    )
    plan = ci_local.plan(workflow)
    assert len(plan) == expected
    assert all(step.action in {"run", "skip"} for step in plan)
    assert all(step.reason for step in plan if step.action == "skip")


def test_tests_lint_types_and_script_checks_always_run() -> None:
    plan = _ci_local().plan(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text()))
    # Only a step that must reach the network (a scanner download, the npm advisory API) may skip a check.
    skipped = [step for step in plan if step.action == "skip" and not any(why in step.reason for why in ("download", "registry"))]
    for marker in ("pytest", "make lint-ruff", "make lint-mypy", "make format-check", "scripts/check_"):
        assert not [step.name for step in skipped if marker in step.command], marker
    shards = [step for step in plan if step.job == "test-shard" and "pytest_ci_plan.py shard" in step.command]
    assert sorted(step.matrix for step in shards) == ["0", "1", "2", "3"]
    assert all("${{" not in step.command for step in plan if step.action == "run")


def test_make_targets_and_pre_push_hook_run_the_parity_script() -> None:
    makefile = (ROOT / "Makefile").read_text()
    assert "ci-local:" in makefile and "ci-smoke:" in makefile
    assert makefile.count("scripts/ci_local.py") >= 2
    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())
    assert "pre-push" in config.get("default_install_hook_types", [])
    hooks = [hook for repo in config["repos"] for hook in repo.get("hooks", [])]
    (smoke,) = [hook for hook in hooks if hook.get("id") == "ci-smoke"]
    assert smoke["entry"] == "make ci-smoke"
    assert smoke["stages"] == ["pre-push"]
