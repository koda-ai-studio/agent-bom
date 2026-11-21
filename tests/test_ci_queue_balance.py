"""Queue scheduling preserves complete proof while distributing expensive suites."""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_unit_tests_run_in_parallel_with_ui_validation_and_are_required():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    unit = jobs["ui-unit"]
    assert unit["needs"] == "changes"
    assert unit["if"] == jobs["ui"]["if"]
    assert unit["strategy"]["matrix"]["shard"] == [1, 2]
    assert "--shard=${{ matrix.shard }}/2" in "\n".join(s.get("run", "") for s in unit["steps"])
    assert "ui-unit" in jobs["test"]["needs"]
    gate = jobs["test"]["steps"][0]
    assert gate["env"]["UI_UNIT_RESULT"] == "${{ needs.ui-unit.result }}"
    assert "UI_UNIT" in gate["run"]


def test_postgres_durations_are_real_nonempty_module_measurements():
    data = json.loads((ROOT / "tests/.ci-postgres-durations.json").read_text())["files"]
    assert len(data) >= 100
    assert sum(data.values()) > 100
    assert all((ROOT / path).is_file() and seconds >= 0 for path, seconds in data.items())


def test_short_deployment_and_docs_checks_share_lint_runner():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    assert not {"compose-contract", "helm-profiles", "docs-strict"} & jobs.keys()
    steps = {s.get("name"): s for s in jobs["lint"]["steps"]}
    for name in [
        "Validate every shipped compose file and overlay combination",
        "Render shipped Helm profiles",
        "Build site (strict, no deploy)",
    ]:
        assert name in steps
        assert "if" in steps[name]
        assert not steps[name].get("continue-on-error")
