from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_release_main_ci.py"
SHA = "d" * 40


def _load_script():
    spec = importlib.util.spec_from_file_location("check_release_main_ci", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fetcher(*, branch_sha: str = SHA, runs: list[dict[str, Any]] | None = None, jobs: list[dict[str, Any]] | None = None):
    run_rows = runs if runs is not None else [_run()]

    def fetch(endpoint: str) -> dict[str, Any]:
        if "/git/ref/heads/" in endpoint:
            return {"object": {"sha": branch_sha}}
        if "/jobs?" in endpoint:
            rows = jobs if jobs is not None else _jobs()
            return {"jobs": rows, "total_count": len(rows)}
        assert "/actions/workflows/ci.yml/runs?" in endpoint
        return {"workflow_runs": run_rows}

    return fetch


def _run(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 123,
        "name": "CI/CD Pipeline",
        "path": ".github/workflows/ci.yml",
        "head_sha": SHA,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "html_url": "https://github.com/msaad00/agent-bom/actions/runs/123",
    }
    row.update(overrides)
    return row


def test_exact_main_completed_success_is_accepted() -> None:
    checker = _load_script()

    proof = checker.verify_release_candidate(
        repo="msaad00/agent-bom",
        sha=SHA,
        branch="main",
        workflow="ci.yml",
        fetch_json=_fetcher(),
    )

    assert proof == {
        "sha": SHA,
        "run_id": 123,
        "run_url": "https://github.com/msaad00/agent-bom/actions/runs/123",
    }


def test_candidate_run_is_found_when_unfiltered_history_omits_it() -> None:
    checker = _load_script()

    def fetch(endpoint: str) -> dict[str, Any]:
        if "/git/ref/heads/" in endpoint:
            return {"object": {"sha": SHA}}
        if "/jobs?" in endpoint:
            return {"jobs": _jobs(), "total_count": len(_jobs())}
        query = parse_qs(urlsplit(endpoint).query)
        # A busy workflow's first history page need not contain this commit.
        rows = [_run()] if query.get("head_sha") == [SHA] else [_run(head_sha="e" * 40)]
        return {"workflow_runs": rows}

    proof = checker.verify_release_candidate(repo="msaad00/agent-bom", sha=SHA, fetch_json=fetch)

    assert proof["sha"] == SHA
    assert proof["run_id"] == 123


def test_stale_candidate_sha_is_rejected_before_ci_lookup() -> None:
    checker = _load_script()

    with pytest.raises(checker.ReleaseProofError, match="does not equal current main"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom",
            sha=SHA,
            branch="main",
            workflow="ci.yml",
            fetch_json=_fetcher(branch_sha="e" * 40),
        )


@pytest.mark.parametrize(
    "run",
    [
        _run(status="in_progress", conclusion=None),
        _run(status="completed", conclusion="cancelled"),
        _run(event="pull_request"),
        _run(head_sha="e" * 40),
        _run(head_branch="feature/release"),
        _run(path=".github/workflows/other.yml"),
    ],
)
def test_only_exact_completed_successful_main_push_proves_release(run: dict[str, Any]) -> None:
    checker = _load_script()

    with pytest.raises(checker.ReleaseProofError, match="completed successful main push"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom",
            sha=SHA,
            branch="main",
            workflow="ci.yml",
            fetch_json=_fetcher(runs=[run]),
        )


def test_lookup_failures_do_not_expose_raw_remote_details() -> None:
    checker = _load_script()

    def fail(_endpoint: str) -> dict[str, Any]:
        raise RuntimeError("Authorization: Bearer secret-token database.internal")

    with pytest.raises(checker.ReleaseProofError) as caught:
        checker.verify_release_candidate(
            repo="msaad00/agent-bom",
            sha=SHA,
            branch="main",
            workflow="ci.yml",
            fetch_json=fail,
        )

    message = str(caught.value)
    assert "release proof lookup failed" in message
    assert "secret-token" not in message
    assert "database.internal" not in message


def test_release_workflow_requires_exact_main_ci_proof() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "release.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    guard = workflow["jobs"]["version-guard"]

    assert guard["permissions"]["actions"] == "read"
    step = next(step for step in guard["steps"] if step.get("name") == "Verify tag commit is exact green main")
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "scripts/check_release_main_ci.py" in step["run"]
    assert '--sha "${{ github.sha }}"' in step["run"]


def test_release_workflow_also_requires_exact_runtime_acceptance() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    steps = workflow["jobs"]["version-guard"]["steps"]
    step = next(step for step in steps if "--workflow runtime-acceptance.yml" in step.get("run", ""))
    assert "scripts/check_release_main_ci.py" in step["run"]
    assert '--sha "${{ github.sha }}"' in step["run"]
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"


def test_runtime_acceptance_proves_every_main_sha() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/runtime-acceptance.yml").read_text())
    assert workflow[True]["push"] == {"branches": ["main"]}


def _runtime_fetcher(*, runs=None, jobs=None):
    run = _run(path=".github/workflows/runtime-acceptance.yml", name="Runtime Helm Acceptance")
    job = {"name": "Gateway ingest and replica reconnect", "head_sha": SHA, "status": "completed", "conclusion": "success"}

    def fetch(endpoint):
        if "/git/ref/heads/" in endpoint:
            return {"object": {"sha": SHA}}
        if "/jobs?" in endpoint:
            rows = [job] if jobs is None else jobs
            return {"jobs": rows, "total_count": len(rows)}
        assert "/actions/workflows/runtime-acceptance.yml/runs?" in endpoint
        return {"workflow_runs": [run] if runs is None else runs}

    return fetch


def test_exact_runtime_acceptance_is_accepted_without_ui_jobs() -> None:
    checker = _load_script()
    proof = checker.verify_release_candidate(
        repo="msaad00/agent-bom", sha=SHA, workflow="runtime-acceptance.yml", fetch_json=_runtime_fetcher()
    )
    assert proof["sha"] == SHA


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", None])
def test_runtime_job_must_complete_successfully(conclusion) -> None:
    checker = _load_script()
    job = {"name": "Gateway ingest and replica reconnect", "head_sha": SHA, "status": "completed", "conclusion": conclusion}
    with pytest.raises(checker.ReleaseProofError, match="job"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom", sha=SHA, workflow="runtime-acceptance.yml", fetch_json=_runtime_fetcher(jobs=[job])
        )


@pytest.mark.parametrize(
    "overrides", [{"head_sha": "e" * 40}, {"event": "pull_request"}, {"conclusion": "failure"}, {"status": "in_progress"}]
)
def test_runtime_run_rejects_stale_pr_failed_and_pending_proof(overrides) -> None:
    checker = _load_script()
    run = _run(path=".github/workflows/runtime-acceptance.yml", **overrides)
    with pytest.raises(checker.ReleaseProofError, match="completed successful main push"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom", sha=SHA, workflow="runtime-acceptance.yml", fetch_json=_runtime_fetcher(runs=[run])
        )


def test_runtime_acceptance_rejects_missing_job() -> None:
    checker = _load_script()
    with pytest.raises(checker.ReleaseProofError, match="Gateway ingest and replica reconnect"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom", sha=SHA, workflow="runtime-acceptance.yml", fetch_json=_runtime_fetcher(jobs=[])
        )


@pytest.mark.parametrize("overrides", [{"head_sha": "e" * 40}, {"status": "queued"}, {"status": "in_progress"}])
def test_runtime_job_rejects_stale_or_incomplete_evidence(overrides) -> None:
    checker = _load_script()
    job = {"name": "Gateway ingest and replica reconnect", "head_sha": SHA, "status": "completed", "conclusion": "success", **overrides}
    with pytest.raises(checker.ReleaseProofError, match="job did not succeed"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom", sha=SHA, workflow="runtime-acceptance.yml", fetch_json=_runtime_fetcher(jobs=[job])
        )


def test_unknown_workflow_has_no_implicit_release_contract() -> None:
    checker = _load_script()
    with pytest.raises(checker.ReleaseProofError, match="unsupported release proof workflow"):
        checker.verify_release_candidate(repo="msaad00/agent-bom", sha=SHA, workflow="unknown.yml", fetch_json=_fetcher())


def _jobs():
    return [
        {"name": name, "status": "completed", "conclusion": "success", "head_sha": SHA}
        for name in ("UI Validate", "UI export build", "UI E2E and container smoke")
    ]


@pytest.mark.parametrize("name", ["UI Validate", "UI export build", "UI E2E and container smoke"])
@pytest.mark.parametrize("conclusion", ["skipped", "failure", "cancelled", None, "missing"])
def test_release_requires_every_ui_lane_to_execute_successfully(name, conclusion):
    checker = _load_script()
    jobs = _jobs()
    if conclusion == "missing":
        jobs = [job for job in jobs if job["name"] != name]
    else:
        next(job for job in jobs if job["name"] == name)["conclusion"] = conclusion
    with pytest.raises(checker.ReleaseProofError, match="UI"):
        checker.verify_release_candidate(repo="msaad00/agent-bom", sha=SHA, fetch_json=_fetcher(jobs=jobs))


@pytest.mark.parametrize("bad_status", ["queued", "in_progress"])
def test_release_rejects_ui_jobs_that_have_not_completed(bad_status):
    checker = _load_script()
    jobs = _jobs()
    jobs[0]["status"] = bad_status
    with pytest.raises(checker.ReleaseProofError, match="UI"):
        checker.verify_release_candidate(repo="msaad00/agent-bom", sha=SHA, fetch_json=_fetcher(jobs=jobs))


def test_release_reads_all_job_pages_from_latest_attempt():
    checker = _load_script()
    pages = []

    def fetch(endpoint):
        if "/jobs?" not in endpoint:
            return _fetcher()(endpoint)
        query = parse_qs(urlsplit(endpoint).query)
        assert query["filter"] == ["latest"]
        page = int(query["page"][0])
        pages.append(page)
        return {"jobs": [{"name": "Other"}] * 100 if page == 1 else _jobs(), "total_count": 103}

    assert checker.verify_release_candidate(repo="msaad00/agent-bom", sha=SHA, fetch_json=fetch)["run_id"] == 123
    assert pages == [1, 2]


def test_release_rejects_job_evidence_for_another_sha():
    checker = _load_script()
    jobs = _jobs()
    jobs[0]["head_sha"] = "e" * 40
    with pytest.raises(checker.ReleaseProofError, match="UI"):
        checker.verify_release_candidate(repo="msaad00/agent-bom", sha=SHA, fetch_json=_fetcher(jobs=jobs))
