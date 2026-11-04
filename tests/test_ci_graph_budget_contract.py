"""Timing gates remain required when correctness runs use parallel workers."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("job_name", ["test-smoke", "test-shard"])
def test_api_timing_budgets_run_without_competing_workers(job_name):
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    steps = jobs[job_name]["steps"]
    budget_steps = [step for step in steps if "tests/test_push_ingest_perf_budget.py" in step.get("run", "")]
    assert len(budget_steps) == 1
    step = budget_steps[0]
    assert step["if"] == "matrix.shard == 0"
    assert "tests/api/test_graph_first_read_budget.py" in step["run"]
    assert "-m graph_performance" in step["run"]
    assert "-n " not in step["run"]
    assert "--cov" not in step["run"]
    assert not step.get("continue-on-error", False)
    correctness = next(step["run"] for step in steps if "--dist worksteal" in step.get("run", ""))
    assert "not graph_performance" in correctness
    suite = (ROOT / "tests/test_push_ingest_perf_budget.py").read_text()
    assert "pytestmark = pytest.mark.graph_performance" in suite


@pytest.mark.parametrize("workflow,job_name", [("ci.yml", "changes"), ("ci.yml", "test-smoke"), ("pr-security-gate.yml", "changes")])
def test_diff_classification_keeps_ancestry_without_historical_blobs(workflow, job_name):
    job = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())["jobs"][job_name]
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["filter"] == "blob:none"


def test_affected_matrix_and_execution_partition_the_same_isolated_budgets():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    for job_name in ("changes", "test-smoke"):
        selection = next(step["run"] for step in jobs[job_name]["steps"] if "pytest_ci_affected.py" in step.get("run", ""))
        assert "--correctness" in selection
    from scripts.pytest_ci_affected import ISOLATED_GRAPH_BUDGETS

    isolated = next(step["run"] for step in jobs["test-smoke"]["steps"] if "-m graph_performance" in step.get("run", ""))
    assert set(ISOLATED_GRAPH_BUDGETS) == {word for word in isolated.split() if word.startswith("tests/")}
