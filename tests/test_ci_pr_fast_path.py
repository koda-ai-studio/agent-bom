"""Pull requests prove the affected selection; the full matrix runs after merge."""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RUNBOOK = ROOT / "docs" / "operations" / "CI_RUNBOOK.md"
EVENTS = ("pull_request", "merge_group", "push", "schedule", "workflow_dispatch")
RESULTS = ("success", "failure", "skipped")
FLAGS = ("true", "false", "")
OUTPUTS = (
    "full_python",
    "alpine",
    "alpine_full",
    "alpine_pr",
    "ui",
    "ui_e2e",
    "ui_container",
    "postgres",
    "python",
    "endpoint",
    "native_image",
)
FULL_SUITE_JOBS = ("test-shard", "test-main", "test-coverage")
AFFECTED_STEP = "Run affected tests and contract smoke"


def _ci() -> dict:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


def _python(expression: str) -> str:
    expression = " ".join(str(expression).strip().removeprefix("${{").removesuffix("}}").split())
    expression = expression.replace("!cancelled()", "True").replace("!(", "not (")
    expression = expression.replace("needs.test-main.", "needs.test_main.")
    return expression.replace("&&", " and ").replace("||", " or ")


def _contexts(event: str):
    """Every classifier result/output combination the event can present."""
    for result in RESULTS:
        for values in itertools.product(FLAGS, repeat=2):
            outputs = {name: values[index % 2] for index, name in enumerate(OUTPUTS)}
            yield {
                "github": SimpleNamespace(event_name=event, ref="refs/heads/main"),
                "needs": SimpleNamespace(
                    changes=SimpleNamespace(result=result, outputs=SimpleNamespace(**outputs)), test_main=SimpleNamespace(result="success")
                ),
            }
    for result in RESULTS:
        for flag in FLAGS:
            yield {
                "github": SimpleNamespace(event_name=event, ref="refs/heads/main"),
                "needs": SimpleNamespace(
                    changes=SimpleNamespace(result=result, outputs=SimpleNamespace(**dict.fromkeys(OUTPUTS, flag))),
                    test_main=SimpleNamespace(result="success"),
                ),
            }


def _runs(job: dict, context: dict) -> bool:
    return bool(eval(_python(job.get("if", "true")), {"__builtins__": {}}, context))


def _step(job: dict, name: str) -> dict:
    return next(step for step in job["steps"] if step.get("name") == name)


def test_pull_request_can_never_select_the_full_suite() -> None:
    """No classifier outcome lets a PR start the full shards or the version matrix."""
    jobs = _ci()["jobs"]
    for name in FULL_SUITE_JOBS:
        for context in _contexts("pull_request"):
            assert not _runs(jobs[name], context), name


def test_pull_request_never_runs_the_full_musl_suite() -> None:
    alpine = _ci()["jobs"]["test-alpine"]
    matrix = alpine["strategy"]["matrix"]["shard"]
    full = _step(alpine, "Run tests (musl)")["env"]["ALPINE_FULL"]
    for expression in (matrix.split("fromJSON(", 1)[1].split(" && '[0, 1, 2, 3]'", 1)[0], full):
        for context in _contexts("pull_request"):
            assert not eval(_python(expression), {"__builtins__": {}}, context), expression


def test_pull_request_never_runs_every_browser_shard() -> None:
    jobs = _ci()["jobs"]
    for context in _contexts("pull_request"):
        assert not _runs(jobs["ui-e2e-shard"], context)


def test_affected_tests_run_on_every_pull_request_input() -> None:
    """Shared, unmapped or unclassified inputs still run the affected selection."""
    job = _ci()["jobs"]["test-smoke"]
    for context in _contexts("pull_request"):
        assert _runs(job, context)
    for event in ("push", "schedule", "workflow_dispatch"):
        assert all(_runs(job, context) for context in _contexts(event)), event
    assert not any(_runs(job, context) for context in _contexts("merge_group"))


def test_affected_job_is_bounded_and_reports_slow_tests() -> None:
    job = _ci()["jobs"]["test-smoke"]
    shards = job["strategy"]["matrix"]["shard"]
    assert job["name"] == f"Python affected tests (shard ${{{{ matrix.shard }}}}/{len(shards)})"
    assert shards == list(range(len(shards))) and len(shards) == 3
    assert job["strategy"]["fail-fast"] is False
    assert job["timeout-minutes"] <= 22
    run = _step(job, AFFECTED_STEP)["run"]
    assert 'AFFECTED_SELECTION=$(uv run python scripts/pytest_ci_affected.py --root . "${CHANGED[@]}")' in run
    assert f'--total {len(shards)} --files "${{TESTS[@]}}"' in run
    assert "--durations=50" in run


def test_full_suite_lanes_report_the_fifty_slowest_tests() -> None:
    jobs = _ci()["jobs"]
    runs = [
        _step(jobs["test-shard"], "Run full correctness shard")["run"],
        _step(jobs["test-main"], "Run full correctness suite")["run"],
        _step(jobs["test-alpine"], "Run tests (musl)")["run"],
    ]
    for run in runs:
        lines = [line for line in run.splitlines() if "uv run pytest" in line]
        assert lines
        assert all("--durations=50" in line for line in lines), lines


def test_merge_groups_and_post_merge_events_keep_full_proof() -> None:
    jobs = _ci()["jobs"]
    assert all(_runs(jobs["test-shard"], context) for context in _contexts("merge_group"))
    for event in ("push", "schedule", "workflow_dispatch"):
        for name in (
            "test-main",
            "ui-e2e-shard",
            "graph-performance",
            "output-scale-performance",
            "sdk-import-smoke",
            "postgres-integration",
        ):
            assert all(_runs(jobs[name], context) for context in _contexts(event)), (event, name)
    assert jobs["test-main"]["strategy"]["matrix"] == {"python-version": ["3.11", "3.12", "3.13", "3.14"], "shard": [0, 1, 2, 3]}
    alpine = _step(jobs["test-alpine"], "Run tests (musl)")["env"]["ALPINE_FULL"]
    nightly = {
        "github": SimpleNamespace(event_name="schedule"),
        "needs": SimpleNamespace(changes=SimpleNamespace(outputs=SimpleNamespace(alpine_full=""))),
    }
    assert eval(_python(alpine), {"__builtins__": {}}, nightly)
    push = {
        "github": SimpleNamespace(event_name="push"),
        "needs": SimpleNamespace(changes=SimpleNamespace(outputs=SimpleNamespace(alpine_full="true"))),
    }
    assert eval(_python(alpine), {"__builtins__": {}}, push)


def test_pull_request_browser_smoke_runs_only_for_ui_inputs() -> None:
    jobs = _ci()["jobs"]
    smoke = jobs["ui-e2e-smoke"]
    assert smoke["name"] == "UI E2E smoke"
    for context in _contexts("pull_request"):
        changes = context["needs"].changes
        assert _runs(smoke, context) == (changes.result != "success" or changes.outputs.ui_e2e != "false")
    for event in ("merge_group", "push", "schedule", "workflow_dispatch"):
        assert not any(_runs(smoke, context) for context in _contexts(event)), event
    run = _step(smoke, "UI E2E smoke")["run"]
    specs = re.findall(r"e2e/[\w-]+\.spec\.ts", run)
    assert specs and all((ROOT / "ui" / spec).is_file() for spec in specs)
    assert "ui-e2e-smoke" in jobs["ui-e2e"]["needs"]


def test_ui_e2e_classifier_selects_ui_sources_only() -> None:
    script = _step(_ci()["jobs"]["changes"], "Classify changed paths")["run"]
    pattern = re.search(r"grep -E '([^']+)' > /dev/null; then\n\s+ui_e2e=true", script)
    assert pattern is not None
    for path in ("ui/app/page.tsx", ".github/actions/setup-ui/action.yml", ".github/workflows/ci.yml"):
        assert re.search(pattern[1], path), path
    for path in ("src/agent_bom/graph/builder.py", "src/agent_bom/api/routes/graph.py", "docs/openapi/openapi.json"):
        assert not re.search(pattern[1], path), path


def test_runbook_required_checks_name_real_jobs() -> None:
    """The documented required checks are exact names GitHub reports."""
    text = RUNBOOK.read_text(encoding="utf-8")
    section = text.split("### Required checks", 1)[1].split("\n#", 1)[0]
    names = re.findall(r"^\d+\. `([^`]+)`", section, re.MULTILINE)
    assert len(names) >= 8
    reported: set[str] = set()
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        reported.update(str(job.get("name", key)) for key, job in (document.get("jobs") or {}).items())
    reported.add("CodeQL")  # the code-scanning app's result context
    assert set(names) <= reported, set(names) - reported
    assert not any("${{" in name for name in names), "matrix job names are not stable contexts"
