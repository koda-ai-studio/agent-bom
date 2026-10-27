"""Regression guards for CI path gating and duplicate-work prevention."""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _ci() -> dict[str, object]:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


def test_main_docker_pulls_authenticate_before_setup_and_build() -> None:
    job = _ci()["jobs"]["docker"]
    assert "github.event_name != 'pull_request'" in job["if"]
    steps = job["steps"]
    login = next(step for step in steps if step.get("uses", "").startswith("docker/login-action@"))
    assert login["with"] == {
        "registry": "docker.io",
        "username": "${{ secrets.DOCKERHUB_USERNAME }}",
        "password": "${{ secrets.DOCKERHUB_READ_TOKEN || secrets.DOCKERHUB_TOKEN }}",
    }
    assert "if" not in login
    assert not login.get("continue-on-error", False)
    for step in steps:
        if step.get("uses", "").startswith(
            ("docker/setup-qemu-action@", "docker/setup-buildx-action@")
        ) or "docker buildx build" in step.get("run", ""):
            assert steps.index(login) < steps.index(step)


def test_native_image_export_is_owned_by_host_validator() -> None:
    steps = _ci()["jobs"]["docker"]["steps"]
    step = next(step for step in steps if step.get("name") == "agent-bom native image tar scan gate")
    script = step["run"]
    # Atomic JSON exports are private (0600). A different container UID makes
    # an otherwise successful scan unreadable to the host validation process.
    assert 'docker run --rm --user "$(id -u):$(id -g)"' in script
    assert "-o /workspace/native-image-scan.json" in script
    assert 'json.load(open("/tmp/native-image-scan.json"))' in script
    assert "if total_packages <= 0:" in script
    assert not step.get("continue-on-error", False)


def test_postgres_registry_credentials_exclude_forks_and_dependabot() -> None:
    service = _ci()["jobs"]["postgres-integration"]["services"]["postgres"]
    trusted = (
        "github.actor != 'dependabot[bot]' && "
        "(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)"
    )
    credentials = service["credentials"]
    # The runner requires non-empty strings whenever these keys are present.
    # Anonymous pulls must receive an empty mapping, never blank key values.
    assert isinstance(credentials, str)
    expression = " ".join(credentials.split())
    assert expression.startswith("${{ fromJSON(")
    assert trusted in expression
    assert "&& secrets.DOCKERHUB_USERNAME && secrets.DOCKERHUB_READ_TOKEN &&" in expression
    assert "toJSON(secrets.DOCKERHUB_USERNAME)" in expression
    assert "toJSON(secrets.DOCKERHUB_READ_TOKEN)" in expression
    assert 'format(\'{{"username":{0},"password":{1}}}\',' in expression
    assert expression.endswith("|| '{}') }}")


def test_native_image_registry_login_excludes_forks_and_dependabot() -> None:
    steps = _ci()["jobs"]["native-image"]["steps"]
    login = next(step for step in steps if step.get("uses", "").startswith("docker/login-action@"))
    assert " ".join(login["if"].split()) == (
        "env.DOCKERHUB_PULL_AUTH == 'true' && "
        "github.actor != 'dependabot[bot]' && "
        "(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)"
    )
    assert login["with"]["username"] == "${{ secrets.DOCKERHUB_USERNAME }}"
    assert login["with"]["password"] == "${{ secrets.DOCKERHUB_READ_TOKEN }}"
    assert not login.get("continue-on-error", False)
    for step in steps:
        if step.get("uses", "").startswith("docker/setup-buildx-action@") or "docker buildx build" in step.get("run", ""):
            assert steps.index(login) < steps.index(step)


def test_dependency_updates_share_one_scheduled_owner() -> None:
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    groups = config["multi-ecosystem-groups"]
    assert set(groups) == {"weekly-maintenance"}
    assert groups["weekly-maintenance"]["schedule"]["interval"] == "weekly"
    assert groups["weekly-maintenance"]["open-pull-requests-limit"] == 1
    for update in config["updates"]:
        assert update["multi-ecosystem-group"] == "weekly-maintenance"
        assert update["patterns"] == ["*"]
        assert update["groups"]["security-updates"]["applies-to"] == "security-updates"

    lock_refresh = yaml.safe_load((ROOT / ".github" / "workflows" / "uv-lock-upgrade.yml").read_text())
    triggers = lock_refresh.get("on", lock_refresh.get(True))
    assert set(triggers) == {"workflow_dispatch"}


def test_timeout_policy_uses_the_locked_security_environment() -> None:
    steps = _ci()["jobs"]["security"]["steps"]
    install = next(step for step in steps if step.get("name") == "Install dependencies")
    timeout = next(step for step in steps if step.get("name") == "Workflow job timeout policy")
    assert steps.index(install) < steps.index(timeout)
    assert "--frozen" in install["run"]
    assert "pip install" not in timeout["run"]
    assert "uv run --no-sync python scripts/check_workflow_timeouts.py" in timeout["run"]


def test_cloud_sdk_drift_uses_checkout_lockfile() -> None:
    path = ROOT / ".github/workflows/cloud-sdk-drift.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["drift"]["steps"]
    scripts = "\n".join(step.get("run", "") for step in steps)
    assert any(step.get("uses") == "./.github/actions/setup-python" for step in steps)
    assert "uv sync --frozen" in scripts
    assert "pip install" not in scripts
    assert "uv run --no-sync python scripts/check_cloud_sdk_drift.py" in scripts


def test_path_classifier_covers_main_pushes() -> None:
    workflow = _ci()
    on = workflow.get(True, workflow.get("on", {}))
    assert isinstance(on, dict)
    assert "push" in on

    changes = workflow["jobs"]["changes"]
    assert "github.event_name == 'pull_request' || github.event_name == 'push'" in changes["if"]
    classify = next(step for step in changes["steps"] if step.get("id") == "classify")
    script = classify["run"]
    assert "status=success" in script
    assert 'git diff --name-only "$comparison_base" "$GITHUB_SHA"' in script
    assert "git ls-files" in script


def test_required_ci_contexts_use_docs_only_fast_paths_without_disappearing() -> None:
    """Branch-protection contexts must report success instead of being path-skipped."""
    jobs = _ci()["jobs"]
    assert "docs_only" in jobs["changes"]["outputs"]

    for name in ("security", "lint", "test", "build"):
        job = jobs[name]
        assert "changes" in job["needs"]
        assert "!cancelled()" in job["if"]

    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/classify_ci_changes.py" in workflow_text
    assert "Documentation-only safety checks" in workflow_text
    assert "Documentation-only test skip" not in workflow_text
    assert "Documentation-only package skip" in workflow_text


def test_non_required_heavy_jobs_are_path_gated() -> None:
    jobs = _ci()["jobs"]
    assert "needs.changes.outputs.helm == 'true'" in jobs["helm-profiles"]["if"]
    assert "needs.changes.result != 'success'" in jobs["helm-profiles"]["if"]


def test_enterprise_demo_contract_is_gated_and_packaged() -> None:
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    deploy_workflow = (ROOT / ".github" / "workflows" / "demo-deploy-cloudrun.yml").read_text(encoding="utf-8")

    assert "scripts/check_enterprise_demo_surfaces.py" in workflow_text
    assert "scripts/check_enterprise_demo_surfaces.py" in makefile
    assert "agent_bom/demo_estate/data/enterprise_observations.jsonl" in workflow_text
    assert "/v1/demo-estate/story" in deploy_workflow
    assert "/v1/demo-estate/status" in deploy_workflow
    assert 'payload["graph_alignment"] == "aligned"' in deploy_workflow
    assert "rate_limited_after_page_2" in deploy_workflow


def test_demo_deploy_new_release_supersedes_stale_approval_wait() -> None:
    """An obsolete protected-environment wait must not block a newer release."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "demo-deploy-cloudrun.yml").read_text(encoding="utf-8"))

    assert workflow["concurrency"] == {
        "group": "demo-deploy-cloudrun",
        "cancel-in-progress": True,
    }


def test_dependency_security_skips_only_proven_docs_only_changes() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "pr-security-gate.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert "scripts/classify_ci_changes.py" in workflow_path.read_text(encoding="utf-8")
    for name in ("code-scanning-config-pr", "pip-audit-pr", "self-scan-pr"):
        condition = jobs[name]["if"]
        assert "needs.changes.result != 'success'" in condition
        assert "needs.changes.outputs.docs_only != 'true'" in condition


def test_npm_audits_use_committed_lockfiles() -> None:
    """Advisory checks must use the bulk API without npm's retired fallback."""
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert ci.count("check_npm_advisories.py package-lock.json") == 2
    assert release.count("check_npm_advisories.py package-lock.json") == 1
    assert "--npm-install-report" not in ci
    assert "--npm-install-report" not in release
    assert ci.count("npm ci --ignore-scripts --no-audit") == 1
    assert release.count("npm ci --ignore-scripts --no-audit") == 1
    assert "npm audit" not in ci
    assert "npm audit" not in release


def test_gitleaks_remains_unconditional_for_documentation_changes() -> None:
    workflow = (ROOT / ".github" / "workflows" / "gitleaks.yml").read_text(encoding="utf-8")
    assert "classify_ci_changes.py" not in workflow
    assert "paths-ignore" not in workflow


def test_main_ui_smoke_covers_every_ui_classifier_surface() -> None:
    """The main-push smoke must mirror paths that make PR UI validation run."""
    workflow = (ROOT / ".github" / "workflows" / "main-ui-smoke.yml").read_text(encoding="utf-8")
    for path in (
        '"ui/**"',
        '"action.yml"',
        '"contracts/**"',
        '"src/agent_bom/api/**"',
        '"src/agent_bom/graph/**"',
        '"src/agent_bom/context_graph.py"',
        '"src/agent_bom/graph/types.py"',
        '"src/agent_bom/models.py"',
    ):
        assert path in workflow


def test_path_gated_jobs_fail_closed_when_classifier_fails() -> None:
    jobs = _ci()["jobs"]
    for name in ("docs-strict", "ui", "ui-e2e", "ui-e2e-smoke", "ui-container-smoke", "endpoint-packaging", "test-alpine"):
        condition = jobs[name]["if"]
        assert "needs.changes.result != 'success'" in condition


def test_path_gated_jobs_remain_cancellable() -> None:
    jobs = _ci()["jobs"]
    for name in (
        "docs-strict",
        "ui",
        "endpoint-packaging",
        "test",
        "sdk-import-smoke",
        "postgres-integration",
        "test-alpine",
        "action-dogfood",
        "ui-e2e",
        "ui-e2e-shard",
        "ui-container-smoke",
        "graph-performance",
        "output-scale-performance",
    ):
        condition = jobs[name]["if"]
        assert "!cancelled()" in condition
        assert "always()" not in condition


def test_postgres_integration_uses_a_persistent_audit_signing_key() -> None:
    """A durable shared audit ledger must never use a process-local key."""
    postgres_env = _ci()["jobs"]["postgres-integration"]["env"]

    assert postgres_env["AGENT_BOM_POSTGRES_URL"]
    assert postgres_env["AGENT_BOM_AUDIT_HMAC_KEY"] == "ci-postgres-audit-signing-key"


def test_postgres_storage_contract_passes_every_listed_suite_to_one_pytest_command() -> None:
    """A missing line continuation would run a suite path as its own shell command."""
    steps = _ci()["jobs"]["postgres-integration"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Run real Postgres storage contract")
    lines = [line.strip() for line in script.strip().splitlines() if line.strip()]

    assert lines[0].startswith("uv run pytest")
    assert all(line.endswith("\\") for line in lines[:-1]), [line for line in lines[:-1] if not line.endswith("\\")]
    listed = {line.rstrip("\\ ").strip() for line in lines[1:]}
    for suite in ("tests/test_tenant_quota_store.py", "tests/test_tenant_graph_retention_store.py", "tests/test_storage_sql.py"):
        assert suite in listed
        assert (ROOT / suite).is_file()


def test_test_job_timeout_leaves_margin_over_observed_worst_case() -> None:
    """Split the workload while retaining a finite ceiling for every main shard."""
    assert _ci()["jobs"]["test-main"]["timeout-minutes"] == 45


def test_changed_domain_timeout_covers_broad_selections() -> None:
    """A broad multi-lane PR measured ~15 minutes per shard (cancelled at 99%); keep headroom, stay bounded."""
    assert _ci()["jobs"]["test-smoke"]["timeout-minutes"] == 22


def test_full_correctness_matrix_covers_every_supported_python_minor() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    supported = {
        classifier.rsplit(" :: ", 1)[-1]
        for classifier in project["classifiers"]
        if classifier.startswith("Programming Language :: Python :: 3.")
    }
    matrix = set(_ci()["jobs"]["test-main"]["strategy"]["matrix"]["python-version"])

    assert matrix == supported


def test_local_test_target_enforces_the_ci_coverage_floor() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    test_target = makefile.split("test:  ## Run unit tests", 1)[1].split("\n\n", 1)[0]

    assert "--cov-fail-under=75" in test_target


def test_version_alignment_fails_fast_when_uv_lock_is_stale() -> None:
    """Reject dependency drift before Docker and full-suite jobs consume runners."""
    steps = _ci()["jobs"]["version-check"]["steps"]
    lock_check_index = next(index for index, step in enumerate(steps) if step.get("name") == "Verify uv lockfile freshness")
    dependency_install_index = next(
        index for index, step in enumerate(steps) if step.get("name") == "Install dependencies for CLI smoke checks"
    )

    assert steps[lock_check_index]["run"] == "uv lock --check"
    assert lock_check_index < dependency_install_index


def test_alpine_full_suite_timeout_leaves_musl_headroom() -> None:
    """Every musl shard retains a finite 45-minute execution ceiling."""
    assert _ci()["jobs"]["test-alpine"]["timeout-minutes"] == 45


def test_alpine_full_suite_uses_bounded_parallelism() -> None:
    """The musl full suite must finish without overcommitting the hosted runner."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    alpine = text.split("      - name: Run tests (musl)", 1)[1].split("  # 3c. Release Surface Consistency Check", 1)[0]
    full_suite = next(line.strip() for line in alpine.splitlines() if 'uv run pytest "${TESTS[@]}"' in line)

    assert "-n 2" in full_suite
    assert "--dist worksteal" in full_suite


def test_alpine_full_suite_shards_without_dropping_coverage() -> None:
    job = _ci()["jobs"]["test-alpine"]
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["shard"] == (
        "${{ fromJSON(((needs.changes.outputs.alpine_full == 'true' && github.event_name != 'pull_request') "
        "|| github.event_name == 'schedule') && '[0, 1, 2, 3]' || '[0]') }}"
    )
    step = next(step for step in job["steps"] if step.get("name") == "Run tests (musl)")
    assert step["shell"] == "bash"
    assert step["env"]["ALPINE_SHARD"] == "${{ matrix.shard }}"
    assert 'scripts/pytest_ci_plan.py shard --index "$ALPINE_SHARD" --total 4' in step["run"]
    assert 'if [ "${#TESTS[@]}" -eq 0 ]; then' in step["run"]
    assert '-m "not network and not slow"' in step["run"]
    assert "not graph_performance" not in step["run"]


def test_pull_request_pytest_reports_slowest_tests() -> None:
    """PR runs surface the slowest tests so timeout regressions have evidence."""
    jobs = _ci()["jobs"]
    smoke_run = next(step["run"] for step in jobs["test-smoke"]["steps"] if step.get("name") == "Run affected tests and contract smoke")
    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")

    assert "--durations=50" in smoke_run
    assert "--durations=50" in main_run
    coverage_line = next(line.strip() for line in main_run.splitlines() if "--cov=agent_bom" in line)
    assert "--cov-fail-under=0" in coverage_line
    assert "--cov-report=" in coverage_line


PR_EXCLUDED_POST_MERGE_JOBS = (
    "graph-performance",
    "output-scale-performance",
    "sdk-import-smoke",
    "action-dogfood",
    "docker",
)


REQUIRED_CI_JOBS = ("security", "lint", "build", "test")
SHARD_STEP = "Run full correctness shard"


def _marker_filter(run: str) -> str:
    return run.split(' -m "', 1)[1].split('"', 1)[0]


def test_pull_requests_run_affected_tests_while_main_keeps_the_matrix() -> None:
    """PRs prove the affected selection; full shards are merge-group only; main keeps the matrix."""
    jobs = _ci()["jobs"]
    assert jobs["test-main"]["if"] == ("${{ !cancelled() && github.event_name != 'pull_request' && github.event_name != 'merge_group' }}")
    assert jobs["test-shard"]["if"] == "${{ !cancelled() && github.event_name == 'merge_group' }}"
    assert "test-queue-shard" not in jobs
    assert "needs.changes.outputs.postgres != 'false'" in jobs["postgres-integration"]["if"]
    assert jobs["test-smoke"]["if"] == "${{ !cancelled() && github.event_name != 'merge_group' }}"
    assert "test-pr-shard" not in jobs
    for name in PR_EXCLUDED_POST_MERGE_JOBS:
        condition = jobs[name]["if"]
        assert "github.event_name != 'pull_request'" in condition, name
        assert "!cancelled()" in condition, name


def test_shards_run_the_whole_suite_on_the_merge_result() -> None:
    jobs = _ci()["jobs"]
    shard = jobs["test-shard"]
    assert shard["name"] == "Full correctness shard (${{ matrix.shard }}, Python 3.13)"
    assert shard["needs"] == "changes"
    assert "ref" not in shard["steps"][0].get("with", {})
    setup = next(step for step in shard["steps"] if step.get("uses") == "./.github/actions/setup-python")
    assert setup["with"]["python-version"] == "3.13"
    assert shard["strategy"]["fail-fast"] is False
    indexes = shard["strategy"]["matrix"]["shard"]
    assert indexes == list(range(len(indexes))) and len(indexes) >= 2
    # The largest graph shard reached 68% at the former 20-minute ceiling.
    assert shard["timeout-minutes"] == 45
    assert "cancel-in-progress" not in shard.get("concurrency", {})

    run = next(step["run"] for step in shard["steps"] if step.get("name") == SHARD_STEP)
    assert f"--total {len(indexes)}" in run
    assert '--index "${{ matrix.shard }}"' in run
    assert "--durations=" in run
    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")
    main_filters = {_marker_filter(line) for line in main_run.splitlines() if "uv run pytest " in line}
    assert main_filters == {_marker_filter(run)}


def test_shards_partition_every_test_module_exactly_once() -> None:
    import subprocess
    import sys

    shard = _ci()["jobs"]["test-shard"]
    total = len(shard["strategy"]["matrix"]["shard"])
    selected: list[str] = []
    for index in range(total):
        result = subprocess.run(
            [sys.executable, "scripts/pytest_ci_plan.py", "shard", "--index", str(index), "--total", str(total)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        lines = result.stdout.split()
        assert lines, index
        selected.extend(lines)
    every = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "tests").rglob("test_*.py") if path.is_file())
    assert len(selected) == len(set(selected))
    assert sorted(selected) == every


def test_required_contexts_report_on_pull_request_and_merge_group() -> None:
    """Required contexts report on every event that can gate a merge."""
    workflow = _ci()
    triggers = workflow.get(True, workflow.get("on", {}))
    assert triggers["merge_group"] == {"types": ["checks_requested"]}
    for name in REQUIRED_CI_JOBS:
        assert workflow["jobs"][name]["if"] == "${{ !cancelled() }}", name
    assert workflow["jobs"]["test"]["name"] == "Test (Python 3.13)"
    for name in ("codeql.yml", "pr-security-gate.yml"):
        other = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
        assert other.get(True, other.get("on", {}))["merge_group"] == {"types": ["checks_requested"]}, name


def test_runbook_keeps_strict_protection_and_documents_pr_shards() -> None:
    """No merge queue is available for this repository, so strict protection stays."""
    runbook = " ".join((ROOT / "docs" / "operations" / "CI_RUNBOOK.md").read_text(encoding="utf-8").split())
    total = len(_ci()["jobs"]["test-shard"]["strategy"]["matrix"]["shard"])
    assert f"split into {total} parallel shards" in runbook
    assert "-F strict=false" not in runbook
    assert "rulesets" not in runbook
    assert "| Merge queue |" not in runbook


def test_main_push_aggregator_requires_the_full_suite() -> None:
    """A green main run must mean every post-merge lane actually passed.

    The release gate (scripts/check_release_main_ci.py) accepts the tag only
    when the exact main SHA has a successful ``ci.yml`` push run, so skipping
    the full suite on main would silently weaken the release proof.
    """
    jobs = _ci()["jobs"]
    core = jobs["test-core"]
    lanes = (
        "test-smoke",
        "test-main",
        "test-shard",
        "graph-performance",
        "output-scale-performance",
        "sdk-import-smoke",
        "postgres-integration",
    )
    for lane in lanes:
        assert lane in core["needs"], lane
    run = next(step["run"] for step in core["steps"] if step.get("name") == "Require every applicable correctness lane")
    assert 'if [ "$EVENT_NAME" != "pull_request" ]' in run
    for variable in ("MAIN_RESULT", "SHARD_RESULT", "GRAPH_RESULT", "OUTPUT_SCALE_RESULT", "SDK_SMOKE_RESULT", "POSTGRES_RESULT"):
        assert f'"${variable}"' in run
    assert core["steps"][0]["env"]["EVENT_NAME"] == "${{ github.event_name }}"

    required = jobs["test"]
    assert required["name"] == "Test (Python 3.13)"
    assert "test-core" in required["needs"]
    assert "docker" in required["needs"]
    docker_required = required["steps"][0]["env"]["DOCKER_REQUIRED"]
    assert "pull_request" not in docker_required
    assert "refs/heads/main" in docker_required


def test_ci_runs_nightly_with_full_musl_suite() -> None:
    workflow = _ci()
    on = workflow.get(True, workflow.get("on", {}))
    assert on["schedule"]
    alpine = workflow["jobs"]["test-alpine"]
    run_step = next(step for step in alpine["steps"] if step.get("name") == "Run tests (musl)")
    assert "github.event_name == 'schedule'" in run_step["env"]["ALPINE_FULL"]


def test_pull_request_classifiers_diff_from_the_merge_base() -> None:
    """A two-dot diff against a newer base pulls main's own commits into the PR.

    ``base.sha`` is main's tip when the PR event fired, not the branch point.
    ``git diff base head`` then lists every file main changed since the branch
    point, so unrelated lanes run and the changed-domain selector over-selects.
    """
    two_dot = 'git diff --name-only "${{ github.event.pull_request.base.sha }}" "${{ github.event.pull_request.head.sha }}"'
    three_dot = 'git diff --name-only "${{ github.event.pull_request.base.sha }}...${{ github.event.pull_request.head.sha }}"'
    for name in ("ci.yml", "pr-security-gate.yml"):
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        assert two_dot not in text, name
        assert three_dot in text, name
    assert CI_WORKFLOW.read_text(encoding="utf-8").count(three_dot) == 2


def test_pr_runs_cancel_superseded_runs_and_every_main_push_completes() -> None:
    # A cancelled main run leaves the README build badge reading "failing"
    # and no verdict for that commit; every main push must finish.
    concurrency = _ci()["concurrency"]
    assert "github.event.pull_request.number" in concurrency["group"]
    assert "github.event_name" in concurrency["group"]
    # Main pushes need distinct groups: disabling cancellation alone still
    # allows GitHub's single pending slot to replace an older queued commit.
    assert "github.event_name == 'push' && github.ref == 'refs/heads/main' && github.sha" in concurrency["group"]
    assert "github.ref" in concurrency["group"]
    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"
    for name in ("codeql.yml", "pr-security-gate.yml"):
        other = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
        assert other["concurrency"]["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}", name


# Lanes each event must prove; every other lane must be skipped or succeed.
# PRs prove the affected selection; merge groups (if a queue is ever enabled)
# prove the sharded 3.13 suite; main, nightly and manual runs prove the matrix.
_EVENT_PROOF = {
    "pull_request": ("SMOKE_RESULT", "POSTGRES_RESULT"),
    "merge_group": (
        "POSTGRES_RESULT",
        "SHARD_RESULT",
        "GRAPH_RESULT",
        "OUTPUT_SCALE_RESULT",
        "SDK_SMOKE_RESULT",
    ),
    "push": (
        "SMOKE_RESULT",
        "POSTGRES_RESULT",
        "MAIN_RESULT",
        "COVERAGE_RESULT",
        "GRAPH_RESULT",
        "OUTPUT_SCALE_RESULT",
        "SDK_SMOKE_RESULT",
    ),
    "schedule": (
        "SMOKE_RESULT",
        "POSTGRES_RESULT",
        "MAIN_RESULT",
        "COVERAGE_RESULT",
        "GRAPH_RESULT",
        "OUTPUT_SCALE_RESULT",
        "SDK_SMOKE_RESULT",
    ),
    "workflow_dispatch": (
        "SMOKE_RESULT",
        "POSTGRES_RESULT",
        "MAIN_RESULT",
        "COVERAGE_RESULT",
        "GRAPH_RESULT",
        "OUTPUT_SCALE_RESULT",
        "SDK_SMOKE_RESULT",
    ),
}


def _run_correctness_gate(event: str, results: dict[str, str]) -> bool:
    import os
    import subprocess

    step = _ci()["jobs"]["test-core"]["steps"][0]
    env = {
        **os.environ,
        **dict.fromkeys(step["env"], "skipped"),
        "EVENT_NAME": event,
        "POSTGRES_REQUIRED": "true",
        **results,
    }
    return subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True).returncode == 0


def test_correctness_gate_requires_exactly_the_lanes_each_event_proves() -> None:
    for event, proof in _EVENT_PROOF.items():
        assert _run_correctness_gate(event, dict.fromkeys(proof, "success")), event
        for lane in proof:
            for outcome in ("failure", "skipped", "cancelled"):
                results = {**dict.fromkeys(proof, "success"), lane: outcome}
                assert not _run_correctness_gate(event, results), (event, lane, outcome)


def test_correctness_gate_rejects_a_failed_lane_that_the_event_does_not_require() -> None:
    for event, proof in _EVENT_PROOF.items():
        for lane in ("MAIN_RESULT", "SHARD_RESULT", "GRAPH_RESULT"):
            if lane in proof:
                continue
            results = {**dict.fromkeys(proof, "success"), lane: "failure"}
            assert not _run_correctness_gate(event, results), (event, lane)


def test_ui_validation_and_e2e_run_in_separate_jobs() -> None:
    jobs = _ci()["jobs"]
    fast = {step.get("name") for step in jobs["ui"]["steps"]}
    assert {"UI lint", "UI tests", "Graph schema codegen — Python ↔ TypeScript drift gate"} <= fast
    assert "UI E2E" not in fast
    assert "UI container smoke test" not in fast

    export = jobs["ui-export"]
    assert "UI static-export build (release parity)" in {step.get("name") for step in export["steps"]}
    assert export["if"] == jobs["ui"]["if"]
    assert "NEXT_EXPORT=1 npm run build" in CI_WORKFLOW.read_text(encoding="utf-8")

    full = {step.get("name") for step in jobs["ui-e2e-shard"]["steps"]}
    assert {"UI production build", "UI bundle budget", "UI E2E smoke"} <= {step.get("name") for step in jobs["ui-e2e-smoke"]["steps"]}
    assert {"UI production build", "UI bundle budget", "UI E2E"} <= full
    assert "UI container smoke test" in {step.get("name") for step in jobs["ui-container-smoke"]["steps"]}
    assert "needs.changes.outputs.ui == 'true'" in jobs["ui-e2e"]["if"]


def test_mypy_cache_is_restored_on_prs_and_saved_only_from_main() -> None:
    steps = _ci()["jobs"]["lint"]["steps"]
    restore = next(step for step in steps if str(step.get("uses", "")).startswith("actions/cache/restore@"))
    save = next(step for step in steps if str(step.get("uses", "")).startswith("actions/cache/save@"))
    mypy = next(step for step in steps if step.get("name") == "MyPy")
    assert steps.index(restore) < steps.index(mypy) < steps.index(save)
    assert restore["with"]["path"] == save["with"]["path"] == ".mypy_cache"
    assert "hashFiles('uv.lock')" in restore["with"]["key"]
    assert "github.event_name == 'push'" in save["if"]
    assert "refs/heads/main" in save["if"]


def test_fuzzing_runs_after_merge_not_on_pull_requests() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/cflite-pr.yml").read_text())
    triggers = workflow.get(True, workflow.get("on", {}))
    assert "pull_request" not in triggers
    assert "push" in triggers and "schedule" in triggers
    main_fuzz = workflow["jobs"]["Main-Fuzzing"]
    assert "github.event_name == 'push'" in main_fuzz["if"]
    run = next(step for step in main_fuzz["steps"] if "run_fuzzers" in str(step.get("uses", "")))
    assert run["with"]["mode"] == "batch"


def test_codeql_pr_analysis_skips_test_code_only() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    init = next(step for step in workflow["jobs"]["analyze-python"]["steps"] if "codeql-action/init" in str(step.get("uses", "")))
    config = yaml.safe_load(init["with"]["config"])
    assert config["paths-ignore"] == ["tests/**"]
    assert init["with"]["queries"] == "security-extended"


def test_runtime_acceptance_is_post_merge_for_broad_api_changes() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/runtime-acceptance.yml").read_text())
    triggers = workflow.get(True, workflow.get("on", {}))
    assert "src/agent_bom/api/**" not in triggers["pull_request"]["paths"]
    assert triggers["push"] == {"branches": ["main"]}
    assert ".github/workflows/runtime-acceptance.yml" in triggers["pull_request"]["paths"]

    alert = yaml.safe_load((ROOT / ".github/workflows/main-failure-alert.yml").read_text())
    watched = alert.get(True, alert.get("on", {}))["workflow_run"]["workflows"]
    assert {"CI/CD Pipeline", "Runtime Helm Acceptance", "ClusterFuzzLite"} <= set(watched)


def test_python_smoke_gate_combines_changed_domain_and_cross_surface_contracts() -> None:
    """Every Python PR gets quick relevant and product-boundary feedback."""
    smoke = _ci()["jobs"]["test-smoke"]
    run = next(step["run"] for step in smoke["steps"] if step.get("name") == "Run affected tests and contract smoke")

    assert "scripts/pytest_ci_affected.py" in run
    assert "tests/test_cli_entry_points.py" in run
    assert "tests/test_product_surface_contract.py" in run
    assert "tests/api/test_api_scan_findings_wiring.py" in run
    assert "tests/api/test_live_export_contracts.py" in run


def test_readme_contracts_run_for_ui_and_documentation_only_changes() -> None:
    """Public presentation edits must fail PR CI before the full main suite."""
    smoke = _ci()["jobs"]["test-smoke"]
    steps = smoke["steps"]
    for step in steps:
        if "uses" in step or step.get("name") in {"Install dependencies", "Run affected tests and contract smoke"}:
            assert step.get("if") is None
    run = next(step["run"] for step in steps if step.get("name") == "Run affected tests and contract smoke")
    for contract in (
        "test_doc_architecture_svgs.py",
        "test_public_frontdoor_contract.py",
        "test_public_docs_cli_alignment.py",
        "test_readme_demo_excerpt.py",
    ):
        assert f"tests/{contract}" in run


def test_required_package_build_starts_immediately() -> None:
    """Build Package is a required context; it must not queue behind other lanes."""
    assert _ci()["jobs"]["build"]["needs"] == ["changes"]


def test_measured_graph_heap_assertion_has_dedicated_conditional_job() -> None:
    """The six-minute scale assertion is required only on relevant PRs and main."""
    workflow = _ci()
    assert "graph_performance" in workflow["jobs"]["changes"]["outputs"]
    graph_job = workflow["jobs"]["graph-performance"]
    run = next(step["run"] for step in graph_job["steps"] if step.get("name") == "Run measured graph scale assertion")
    assert "-m graph_performance" in run

    graph_test = (ROOT / "tests" / "graph" / "test_store_backed_build_wiring.py").read_text(encoding="utf-8")
    assert "@pytest.mark.graph_performance" in graph_test

    nightly = (ROOT / ".github" / "workflows" / "perf-scale-evidence.yml").read_text(encoding="utf-8")
    assert "-m graph_performance" in nightly


def test_trace_capacity_is_opt_in_bounded_and_preserves_every_attempt() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/perf-scale-evidence.yml").read_text())
    triggers = workflow.get(True, workflow.get("on", {}))
    assert triggers["workflow_dispatch"]["inputs"]["trace_collection"]["default"] is False
    job = workflow["jobs"]["trace-collection"]
    assert job["if"] == "github.event_name == 'workflow_dispatch' && inputs.trace_collection == true"
    assert job["permissions"] == {"contents": "read"}
    assert job["timeout-minutes"] <= 20
    run = next(step["run"] for step in job["steps"] if step.get("name") == "Measure all three bounded runs")
    for required in (
        "for attempt in 1 2 3",
        "CPUQuota=200%",
        "MemoryMax=2G",
        "AGENT_BOM_WORKER_THREAD_LIMIT=2",
        "AGENT_BOM_EXPERIMENTAL=traces",
        "--workers 3 --pages 10 --rows 100",
        "--p95-limit-ms 5000 --slowdown-limit 4",
        "status=1",
        'exit "$status"',
    ):
        assert required in run
    assert "continue-on-error" not in job
    artifact = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert artifact["if"] == "always()"
    for receipt in ("*/receipt.json", "*/attempts.jsonl", "*.log", "resources.txt"):
        assert receipt in artifact["with"]["path"]


def test_output_scale_budgets_run_in_a_dedicated_uninstrumented_lane() -> None:
    """Wall-clock budgets must not share coverage/xdist CPU with the full suite."""

    jobs = _ci()["jobs"]
    scale_job = jobs["output-scale-performance"]
    run = next(step["run"] for step in scale_job["steps"] if step.get("name") == "Run measured output scale assertions")
    setup = next(step for step in scale_job["steps"] if step.get("uses") == "./.github/actions/setup-python")

    assert setup["with"]["python-version"] == "3.11"
    assert scale_job["needs"] == "changes"
    assert "github.event_name != 'pull_request'" in scale_job["if"]
    assert "tests/test_release_output_scale_contract.py" in run
    assert "-m output_performance" in run
    assert "--cov" not in run
    assert " -n " not in run

    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")
    assert "not slow" in main_run

    core = jobs["test-core"]
    assert "output-scale-performance" in core["needs"]
    core_run = next(step["run"] for step in core["steps"] if step.get("name") == "Require every applicable correctness lane")
    assert "OUTPUT_SCALE_RESULT" in core_run
    assert '"$OUTPUT_SCALE_RESULT"' in core_run

    scale_test = (ROOT / "tests" / "test_release_output_scale_contract.py").read_text(encoding="utf-8")
    assert "pytest.mark.slow" in scale_test
    assert "pytest.mark.output_performance" in scale_test


def test_scan_scale_budgets_run_in_the_measured_post_merge_lane() -> None:
    """The 40k-package and reference-image scale checks run uninstrumented, after merge."""

    jobs = _ci()["jobs"]
    scale_job = jobs["output-scale-performance"]
    run = next(step["run"] for step in scale_job["steps"] if step.get("name") == "Run measured scan scale assertions")

    assert "tests/test_scan_scale_contract.py" in run
    assert "tests/test_image_reference_cve_parity.py" in run
    assert "-m scan_performance" in run
    assert "--cov" not in run
    assert " -n " not in run
    assert scale_job["timeout-minutes"] >= 20
    for name in ("test_scan_scale_contract.py", "test_image_reference_cve_parity.py"):
        source = (ROOT / "tests" / name).read_text(encoding="utf-8")
        assert "pytest.mark.slow" in source
        assert "pytest.mark.scan_performance" in source


def test_security_reuses_typescript_install_for_build() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    security = text.split("  # 2. Linting + Type Checking", 1)[0]
    assert security.count("npm ci --ignore-scripts") == 1
    assert "The preceding SDK audit step installed this exact lockfile" in security


def test_graph_guard_does_not_rerun_full_graph_tests() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    guard = text.split("      - name: Graph accuracy fixture guard", 1)[1].split("      - name: DCM scanner self-check", 1)[0]
    assert "pytest" not in guard
    assert "rebaseline_graph_edges.py --dry-run" in guard


def test_stranded_ci_recovery_runs_on_pr_synchronize() -> None:
    workflow = (ROOT / ".github" / "workflows" / "auto-retrigger-stranded.yml").read_text(encoding="utf-8")
    assert "  pull_request:" in workflow
    assert "    types: [synchronize]" in workflow
    assert "scripts/dispatch_required_ci.sh" in workflow
    assert "scripts/retrigger_stranded_pr.sh" in workflow
    assert "github.event.pull_request.number" in workflow
    assert "github.event_name == 'pull_request' && '0' || '3'" in workflow


def test_self_scan_upload_filters_first_party_informational_skill_rows() -> None:
    pr_gate = (ROOT / ".github" / "workflows" / "pr-security-gate.yml").read_text(encoding="utf-8")
    post_merge = (ROOT / ".github" / "workflows" / "post-merge-self-scan.yml").read_text(encoding="utf-8")
    assert "filter_first_party_skill_sarif.py" in pr_gate
    assert "filter_first_party_skill_sarif.py" in post_merge


def test_ci_lint_scope_is_defined_once_in_the_makefile() -> None:
    """CI and ``make lint`` must not hold separate opinions about what is linted.

    They did: CI ran ``ruff check src/`` while the Makefile ran ``src/ tests/``,
    and neither covered ``scripts/`` — where the release gates, drift checks and
    documentation generators live. A dead local in
    ``scripts/generate_doc_architecture_svgs.py`` sat on ``main`` because no gate
    could see it.
    """
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    lint_paths = next(line.split(":=", 1)[1].split() for line in makefile.splitlines() if line.startswith("LINT_PATHS"))
    for required in ("src/", "tests/", "scripts/"):
        assert required in lint_paths, f"{required} is outside the linted scope"

    lint_steps = _ci()["jobs"]["lint"]["steps"]
    ruff = next(step for step in lint_steps if step.get("name") == "Ruff")
    assert "make lint-ruff" in ruff["run"], "CI must call the Makefile target, not restate the paths"
    assert "ruff check" not in ruff["run"], "CI restated the lint paths instead of reusing LINT_PATHS"


def test_dependency_review_keeps_mmh3_license_exception_package_scoped() -> None:
    """A metadata false positive must not globally allow CC-BY software."""
    workflow = (ROOT / ".github" / "workflows" / "dependency-review.yml").read_text(encoding="utf-8")
    global_allowlist = workflow.split("allow-licenses:", 1)[1].split("# Packages whitelisted by PURL:", 1)[0]

    assert "pkg:pypi/mmh3" in workflow
    assert "CC-BY-4.0" not in global_allowlist
    assert "bibliography metadata" in workflow
    assert "sdist declare MIT" in workflow


def test_dependency_review_keeps_caniuse_license_exception_package_scoped() -> None:
    """Browser compatibility data must not globally allow CC-BY software."""
    workflow = (ROOT / ".github" / "workflows" / "dependency-review.yml").read_text(encoding="utf-8")
    global_allowlist = workflow.split("allow-licenses:", 1)[1].split("# Packages whitelisted by PURL:", 1)[0]

    assert "pkg:npm/caniuse-lite" in workflow
    assert "CC-BY-4.0" not in global_allowlist
    assert "browser compatibility data" in workflow
    assert "build tooling" in workflow


def test_dependency_review_accepts_regex_declared_dual_license() -> None:
    """The regex wheel accurately declares its inherited CPython license."""
    workflow = (ROOT / ".github" / "workflows" / "dependency-review.yml").read_text(encoding="utf-8")
    global_allowlist = workflow.split("allow-licenses:", 1)[1].split("# Packages whitelisted by PURL:", 1)[0]

    assert "Apache-2.0" in global_allowlist
    assert "CNRI-Python" in global_allowlist
    assert "derived from CPython 2.6/3.1" in workflow


def test_alpine_installs_jq_for_registry_selector_contracts() -> None:
    """The full musl suite executes jq, including after bootstrap retries."""
    steps = _ci()["jobs"]["test-alpine"]["steps"]
    install = next(step for step in steps if step.get("name") == "Install build deps (Alpine)")
    commands = [line for line in install["run"].splitlines() if "apk add --no-cache" in line]
    assert commands
    assert all("jq" in command.replace(";", " ").split() for command in commands)


def test_pip_audit_reuses_only_proven_identical_dependency_inputs() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/pr-security-gate.yml").read_text())
    jobs = workflow["jobs"]
    assert "python_dependencies" in jobs["changes"]["outputs"]
    steps = jobs["pip-audit-pr"]["steps"]
    reuse = next(step for step in steps if step.get("name") == "Reuse audit for unchanged Python dependency inputs")
    base = next(step for step in steps if step.get("name") == "Run pip-audit on PR base for delta comparison")
    assert "github.event_name == 'pull_request'" in reuse["if"]
    assert "needs.changes.result == 'success'" in reuse["if"]
    assert "needs.changes.outputs.python_dependencies == 'false'" in reuse["if"]
    assert reuse["run"] == "cp audit.json base-audit.json"
    assert "needs.changes.result != 'success'" in base["if"]
    assert "needs.changes.outputs.python_dependencies != 'false'" in base["if"]
    assert "github.event.pull_request.base.sha" in base["run"]
    assert "github.base_ref" not in base["run"]
    evaluate = next(step for step in steps if step.get("name") == "Evaluate pip-audit gate")
    assert "--mode delta" in evaluate["run"] and "--mode strict" in evaluate["run"]


def test_codeql_skips_only_prose_image_pushes_and_preserves_required_pr_checks() -> None:
    from fnmatch import fnmatch

    workflow = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    triggers = workflow.get(True, workflow.get("on", {}))
    ignores = triggers["push"]["paths-ignore"]
    for path in ("README.md", "docs/operator.md", "docs/images/dashboard.png"):
        assert any(fnmatch(path, pattern) for pattern in ignores)
    # Mixed changes still trigger: code, dependency inputs and unknown files
    # must never match the prose/image-only exclusion list.
    for path in ("src/agent_bom/proxy.py", "docs/example.py", ".github/workflows/ci.yml", "uv.lock", "pyproject.toml", "new-input"):
        assert not any(fnmatch(path, pattern) for pattern in ignores)
    for event in ("pull_request", "merge_group"):
        assert "paths" not in triggers[event]
        assert "paths-ignore" not in triggers[event]
    assert "schedule" in triggers and "workflow_dispatch" in triggers
    assert set(workflow["jobs"]) == {"analyze-python", "analyze-actions"}


def test_keycloak_image_participates_in_dependency_maintenance() -> None:
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert any(update["package-ecosystem"] == "docker" and update.get("directory") == "/deploy/keycloak" for update in config["updates"])


def test_postgres_contract_suites_are_arguments_to_one_pytest_invocation() -> None:
    import shlex

    steps = _ci()["jobs"]["postgres-integration"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Run real Postgres storage contract")
    commands = [line.strip() for line in script.replace("\\\n", " ").splitlines() if line.strip()]
    assert len(commands) == 1, "A missing shell continuation runs a test file as a command"
    arguments = shlex.split(commands[0])
    assert arguments[:3] == ["uv", "run", "pytest"]
    assert "tests/test_tenant_quota_store.py" in arguments
    assert "tests/test_jit_grant_tenant_boundary.py" in arguments
    assert "tests/test_identity_policy_tenant_boundary.py" in arguments
    assert "tests/test_findings_sql_read_contract.py" in arguments
    assert "tests/test_findings_sql_backfill.py" in arguments
    assert "tests/test_findings_current_sql_contract.py" in arguments
    assert "tests/test_jobs_tenant_key_contract.py" in arguments
    assert "tests/test_jobs_dispatch_postgres.py" in arguments


def test_ui_first_failure_diagnostics_survive_without_retries() -> None:
    job = _ci()["jobs"]["ui-e2e-shard"]
    steps = job["steps"]
    uploads = [step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(uploads) == 1, "Retain first-attempt browser failures before the runner disappears"
    upload = uploads[0]
    assert "failure()" in upload["if"] and "cancelled()" in upload["if"]
    assert upload["with"]["name"].endswith("-shard-${{ matrix.shard }}"), "each shard keeps its own diagnostics"
    assert steps.index(upload) > next(index for index, step in enumerate(steps) if step.get("name") == "UI E2E")
    assert upload["with"]["retention-days"] <= 3
    assert set(upload["with"]["path"].splitlines()) == {
        "ui/test-results/**/trace.zip",
        "ui/test-results/**/test-failed-*.png",
        "ui/test-results/**/error-context.md",
    }
    # Uploaded traces must stay within the public synthetic-fixture CI lane.
    e2e = next(step for step in steps if step.get("name") == "UI E2E")
    assert e2e["env"]["GRAPH_SCAN_ARTIFACT"] == ""
    assert "${{ secrets." not in yaml.safe_dump(job)
    config = (ROOT / "ui" / "playwright.config.ts").read_text()
    assert 'trace: "retain-on-failure"' in config
    assert 'screenshot: "only-on-failure"' in config


def test_action_classifier_includes_the_cyclonedx_dogfood_fixture() -> None:
    import re

    steps = _ci()["jobs"]["changes"]["steps"]
    script = next(step["run"] for step in steps if step.get("id") == "classify")
    pattern = re.search(r"grep -E '([^']+)' > /dev/null; then\n\s+action=true", script)
    assert pattern is not None
    for path in ("action.yml", "tests/fixtures/test-sbom.cdx.json", "tests/fixtures/test-policy.json"):
        assert re.search(pattern[1], path), path
    assert not re.search(pattern[1], "docs/readme.md")


def test_every_main_push_runs_all_release_ui_lanes():
    for name in ("ui", "ui-export", "ui-e2e", "ui-e2e-shard", "ui-container-smoke"):
        condition = _ci()["jobs"][name]["if"]
        assert "github.event_name == 'push'" in condition
        assert "github.ref == 'refs/heads/main'" in condition


def test_endpoint_qualification_runs_natively_and_retains_failed_receipts():
    import re

    jobs = _ci()["jobs"]
    script = next(step["run"] for step in jobs["changes"]["steps"] if step.get("id") == "classify")
    pattern = re.search(r"grep -E '([^']+)' > /dev/null; then\n\s+endpoint=true", script)
    assert pattern is not None
    for path in ("src/agent_bom/endpoint/inventory.py", "scripts/qualify_endpoint_collectors.py", "tests/test_endpoint_inventory.py"):
        assert re.search(pattern[1], path), path
    job = jobs["endpoint-packaging"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-latest", "macos-latest", "windows-2022"}
    qualification = next(step for step in job["steps"] if "qualify_endpoint_collectors.py" in step.get("run", ""))
    assert not qualification.get("continue-on-error", False)
    artifact = next(step for step in job["steps"] if step.get("with", {}).get("name", "").startswith("endpoint-qualification-"))
    assert artifact["if"] == "always()"
    assert artifact["with"]["path"] == qualification["env"]["QUALIFICATION_OUTPUT"]
    assert artifact["with"]["if-no-files-found"] == "error"


def test_compatibility_lanes_follow_paths_on_prs_and_fail_closed() -> None:
    from types import SimpleNamespace

    jobs = _ci()["jobs"]
    # PRs gate musl on alpine_pr (dependency/build/workflow inputs); main pushes on alpine.
    for name, flag in (("test-alpine", {"pull_request": "alpine_pr", "push": "alpine"}), ("ui-e2e", {"pull_request": "ui", "push": "ui"})):
        condition = " ".join(jobs[name]["if"].split()).replace("!cancelled()", "True")
        condition = condition.replace("&&", "and").replace("||", "or")
        for event in ("pull_request", "push", "schedule", "workflow_dispatch", "merge_group"):
            for result in ("success", "failure", "skipped"):
                for changed in ("true", "false"):
                    outputs = {"alpine": "false", "alpine_pr": "false", "ui": "false", flag.get(event, "ui"): changed}
                    context = {
                        "github": SimpleNamespace(event_name=event, ref="refs/heads/main"),
                        "needs": SimpleNamespace(changes=SimpleNamespace(result=result, outputs=SimpleNamespace(**outputs))),
                    }
                    expected = event not in ("pull_request", "push") or result != "success" or changed == "true"
                    if name == "ui-e2e" and event == "push":
                        expected = True
                    assert eval(condition, {"__builtins__": {}}, context) == expected, (name, event, result, changed)


def test_ci_and_ui_setup_changes_exercise_ui_validation() -> None:
    import re

    script = next(step["run"] for step in _ci()["jobs"]["changes"]["steps"] if step.get("id") == "classify")
    pattern = re.search(r"grep -E '([^']+)' > /dev/null; then\n\s+ui=true", script)
    assert pattern is not None
    for path in (".github/workflows/ci.yml", ".github/actions/setup-ui/action.yml", "ui/e2e/explore.spec.ts"):
        assert re.search(pattern[1], path), path
    assert not re.search(pattern[1], "docs/operator.md")


def test_required_context_rejects_missing_or_failed_compatibility_proof() -> None:
    import os
    import subprocess

    job = _ci()["jobs"]["test"]
    assert {"test-alpine", "ui-e2e"} <= set(job["needs"])
    step = job["steps"][0]
    base = {**os.environ, "CORE_RESULT": "success", "DOCKER_RESULT": "skipped", "DOCKER_REQUIRED": "false"}
    for required in ("true", "false"):
        for outcome in ("success", "skipped", "failure", "cancelled"):
            for lane in ("ALPINE", "UI_E2E"):
                env = {
                    **base,
                    "ALPINE_REQUIRED": "false",
                    "ALPINE_RESULT": "skipped",
                    "UI_E2E_REQUIRED": "false",
                    "UI_E2E_RESULT": "skipped",
                    f"{lane}_REQUIRED": required,
                    f"{lane}_RESULT": outcome,
                }
                result = subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True)
                expected = outcome == "success" or (outcome == "skipped" and required == "false")
                assert (result.returncode == 0) == expected, (lane, required, outcome)


def test_changed_domain_smoke_distributes_large_test_modules_between_workers() -> None:
    job = _ci()["jobs"]["test-smoke"]
    command = next(step["run"] for step in job["steps"] if step.get("name") == "Run affected tests and contract smoke")
    assert '-n "$WORKERS" --dist worksteal' in command
    assert "-v --tb=short" in command


def test_changed_domain_smoke_shards_keep_every_selected_test_required() -> None:
    jobs = _ci()["jobs"]
    smoke = jobs["test-smoke"]
    assert smoke["strategy"] == {"fail-fast": False, "matrix": {"shard": [0, 1, 2]}}
    command = next(step["run"] for step in smoke["steps"] if step.get("name") == "Run affected tests and contract smoke")
    assert 'scripts/pytest_ci_plan.py shard --index "${{ matrix.shard }}" --total 3 --files "${TESTS[@]}"' in command
    assert 'if [ "${#TESTS[@]}" -eq 0 ]' in command
    assert '[ -z "${TESTS[0]}" ]' in command
    assert "test-smoke" in jobs["test-core"]["needs"]
    assert "test-core" in jobs["test"]["needs"]
    gate = next(step for step in jobs["test-core"]["steps"] if step.get("name") == "Require every applicable correctness lane")
    assert gate["env"]["SMOKE_RESULT"] == "${{ needs.test-smoke.result }}"
    assert 'elif [ "$SMOKE_RESULT" != "success" ]; then' in gate["run"]


def test_affected_tests_are_required_unless_merge_group_shards_replace_them() -> None:
    """A PR must prove the affected tests; a merge group proves the full shards instead."""
    base = {"POSTGRES_REQUIRED": "false", "SHARD_RESULT": "skipped"}
    for smoke in ("success", "skipped", "failure", "cancelled"):
        assert _run_correctness_gate("pull_request", {**base, "SMOKE_RESULT": smoke}) == (smoke == "success"), smoke
    full = {
        "POSTGRES_REQUIRED": "false",
        "GRAPH_RESULT": "success",
        "OUTPUT_SCALE_RESULT": "success",
        "SDK_SMOKE_RESULT": "success",
    }
    for smoke in ("success", "skipped", "failure", "cancelled"):
        for shard in ("success", "skipped", "failure", "cancelled"):
            expected = smoke in ("success", "skipped") and shard == "success"
            outcome = _run_correctness_gate("merge_group", {**full, "SMOKE_RESULT": smoke, "SHARD_RESULT": shard})
            assert outcome == expected, (smoke, shard)
    for event in ("push", "schedule", "workflow_dispatch"):
        proof = dict.fromkeys(_EVENT_PROOF[event], "success")
        assert not _run_correctness_gate(event, {**proof, "SMOKE_RESULT": "skipped"}), event


def test_smoke_and_full_shards_are_complementary_on_merge_gating_events() -> None:
    """Exactly one Python lane runs per PR or merge group; post-merge events keep smoke."""
    from types import SimpleNamespace

    jobs = _ci()["jobs"]

    def _condition(name: str) -> str:
        expression = jobs[name]["if"].removeprefix("${{").removesuffix("}}").strip()
        expression = expression.replace("!cancelled()", "True").replace("!(", "not (")
        return expression.replace("&&", "and").replace("||", "or")

    smoke, shard = _condition("test-smoke"), _condition("test-shard")
    for event in ("pull_request", "merge_group", "push", "schedule", "workflow_dispatch"):
        for result in ("success", "failure", "skipped"):
            for full in ("true", "false", ""):
                context = {
                    "github": SimpleNamespace(event_name=event),
                    "needs": SimpleNamespace(changes=SimpleNamespace(result=result, outputs=SimpleNamespace(full_python=full))),
                }
                runs_smoke = eval(smoke, {"__builtins__": {}}, context)
                runs_shard = eval(shard, {"__builtins__": {}}, context)
                if event == "merge_group":
                    assert runs_shard and not runs_smoke, (event, result, full)
                else:
                    assert runs_smoke and not runs_shard, (event, result, full)


def test_full_shards_cover_everything_the_skipped_smoke_proved() -> None:
    """Skipping smoke must not drop its extras, guards or contract modules."""
    jobs = _ci()["jobs"]
    smoke, shard = jobs["test-smoke"], jobs["test-shard"]

    def _extras(job: dict) -> set[str]:
        install = next(step["run"] for step in job["steps"] if step.get("name") == "Install dependencies")
        return {part.split()[0] for part in install.split("--extra ")[1:]}

    assert _extras(smoke) <= _extras(shard)
    smoke_guards = {step["name"]: step for step in smoke["steps"] if step.get("name", "").startswith(("Graph accuracy", "DCM scanner"))}
    shard_guards = {step["name"]: step for step in shard["steps"] if step.get("name", "").startswith(("Graph accuracy", "DCM scanner"))}
    assert set(smoke_guards) == set(shard_guards) and len(smoke_guards) == 2
    for name, step in shard_guards.items():
        assert step["run"] == smoke_guards[name]["run"], name
        assert "matrix.shard == 0" in step["if"], name
        assert "needs.changes.outputs.python == 'true'" in step["if"], name
        assert "needs.changes.result != 'success'" in step["if"], name


def test_correctness_pytest_lanes_use_every_runner_core() -> None:
    """Workers come from the CPU/memory-aware helper, never a fixed two."""
    jobs = _ci()["jobs"]
    runs = [
        next(step["run"] for step in jobs["test-smoke"]["steps"] if step.get("name") == "Run affected tests and contract smoke"),
        next(step["run"] for step in jobs["test-shard"]["steps"] if step.get("name") == SHARD_STEP),
        next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite"),
    ]
    for run in runs:
        assert 'WORKERS=$(uv run python scripts/ci_pytest_workers.py "${TESTS[@]}")' in run
        assert run.index("WORKERS=$(") < run.index("uv run pytest ")
        lines = [line for line in run.splitlines() if "uv run pytest " in line]
        assert lines
        for line in lines:
            assert '-n "$WORKERS" --dist worksteal' in line, line
            assert "-n 2" not in line, line


def test_optional_correctness_lanes_require_success_when_selected() -> None:
    for required in ("true", "false", ""):
        for result in ("success", "skipped", "failure", "cancelled"):
            outcomes = {"SMOKE_RESULT": "success", "POSTGRES_REQUIRED": required, "POSTGRES_RESULT": result}
            expected = result == "success" or (result == "skipped" and required == "false")
            assert _run_correctness_gate("pull_request", outcomes) == expected, (required, result)
    for result in ("success", "skipped", "failure", "cancelled"):
        outcomes = {"SMOKE_RESULT": "success", "POSTGRES_REQUIRED": "false", "SHARD_RESULT": result}
        assert _run_correctness_gate("pull_request", outcomes) == (result in ("success", "skipped")), result


def test_full_and_postgres_conditions_fail_closed_on_missing_flags() -> None:
    from types import SimpleNamespace

    for name, flag in (("postgres-integration", "postgres"),):
        condition = _ci()["jobs"][name]["if"].removeprefix("${{").removesuffix("}}").strip()
        condition = condition.replace("!cancelled()", "True").replace("&&", "and").replace("||", "or")
        for result in ("success", "failure", "skipped"):
            for changed in ("true", "false", ""):
                context = {
                    "github": SimpleNamespace(event_name="pull_request"),
                    "needs": SimpleNamespace(changes=SimpleNamespace(result=result, outputs=SimpleNamespace(**{flag: changed}))),
                }
                assert eval(condition, {"__builtins__": {}}, context) == (result != "success" or changed != "false")


def test_ui_container_and_duplicate_smoke_guards_are_conditional() -> None:
    jobs = _ci()["jobs"]
    container = jobs["ui-container-smoke"]
    assert "needs.changes.outputs.ui_container != 'false'" in container["if"]
    assert "github.event_name != 'pull_request'" in container["if"]
    for step in jobs["test-smoke"]["steps"]:
        if step.get("name", "").startswith(("Graph accuracy", "DCM scanner")):
            assert "matrix.shard == 0" in step["if"]


def test_changed_domain_selector_failure_is_not_hidden_by_process_substitution() -> None:
    run = next(step["run"] for step in _ci()["jobs"]["test-smoke"]["steps"] if step.get("name") == "Run affected tests and contract smoke")
    assert "AFFECTED_SELECTION=$(uv run python scripts/pytest_ci_affected.py" in run
    assert "mapfile -t TARGETED < <(" not in run


def test_workflow_classifier_combines_writer_and_shared_input_routing(tmp_path) -> None:
    import os
    import re
    import subprocess

    script = next(step["run"] for step in _ci()["jobs"]["changes"]["steps"] if step.get("id") == "classify")
    script = script.replace("${{ github.event_name }}", "pull_request")
    script = re.sub(r"\$\{\{.*?\}\}", "fixture-sha", script)
    script = 'git() { printf "%s\\n" "$TEST_CHANGED_PATHS"; }\n' + script
    for paths, expected in (
        ("README.md", {"full_python": "false", "postgres": "false", "ui": "false"}),
        ("ui/app/page.tsx", {"full_python": "false", "postgres": "false", "ui": "true", "ui_container": "false"}),
        ("ui/Dockerfile", {"ui": "true", "ui_container": "true"}),
        ("src/agent_bom/cloud/side_scan_lifecycle.py", {"postgres": "true"}),
        ("src/agent_bom/models.py", {"full_python": "true", "postgres": "true"}),
        ("scripts/pytest_ci_plan.py", {"full_python": "true"}),
        ("new-surface/unknown.data", {"full_python": "true", "postgres": "true", "ui": "true"}),
    ):
        output = tmp_path / "outputs"
        output.write_text("")
        env = {
            **os.environ,
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            "TEST_CHANGED_PATHS": paths,
            "GITHUB_SHA": "fixture-sha",
        }
        subprocess.run(["bash", "-c", script], cwd=ROOT, env=env, check=True, capture_output=True, text=True)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        for key, value in expected.items():
            assert values[key] == value, (paths, key, values)


def test_main_matrix_partitions_each_interpreter_and_retains_coverage_artifacts() -> None:
    job = _ci()["jobs"]["test-main"]
    assert job["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]
    run = next(step["run"] for step in job["steps"] if step.get("name") == "Run full correctness suite")
    assert 'scripts/pytest_ci_plan.py shard --index "${{ matrix.shard }}" --total 4' in run
    assert '"${TESTS[@]}"' in run
    assert 'if [ "${#TESTS[@]}" -eq 0 ]; then' in run
    assert "--cov-report= --cov-fail-under=0" in run
    upload = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["if"] == "matrix.python-version == '3.11'"
    assert upload["with"]["include-hidden-files"] is True
    assert upload["with"]["if-no-files-found"] == "error"
    assert "${{ matrix.shard }}" in upload["with"]["name"]
    assert "${{ github.run_attempt }}" in upload["with"]["name"]
    assert not upload["with"].get("overwrite", False)


def test_main_coverage_cannot_be_skipped_or_lower_the_combined_floor() -> None:
    jobs = _ci()["jobs"]
    coverage = jobs["test-coverage"]
    assert coverage["needs"] == "test-main"
    assert "needs.test-main.result == 'success'" in coverage["if"]
    run = next(step["run"] for step in coverage["steps"] if step.get("name") == "Require complete combined coverage")
    assert "scripts/combine_ci_coverage.py" in run
    assert "--shards 4" in run
    assert '"${{ github.run_attempt }}"' in run
    assert "test-coverage" in jobs["test-core"]["needs"]
    assert jobs["test-core"]["steps"][0]["env"]["COVERAGE_RESULT"] == "${{ needs.test-coverage.result }}"


def test_lockfile_only_ui_advisory_has_no_dependency_install() -> None:
    steps = _ci()["jobs"]["security"]["steps"]
    audit = next(step for step in steps if step.get("name") == "npm bulk advisory gate (ui/ transitive deps)")
    assert "check_npm_advisories.py" in audit["run"]
    assert "npm ci" not in audit["run"]
    assert "npm config" not in audit["run"]


def test_main_has_one_blocking_installed_dependency_scan_plus_nightly_alerts() -> None:
    gate = yaml.safe_load((ROOT / ".github/workflows/pr-security-gate.yml").read_text())
    post = yaml.safe_load((ROOT / ".github/workflows/post-merge-self-scan.yml").read_text())
    assert "push" in gate[True]
    assert "--fail-on-severity high" in next(s["run"] for s in gate["jobs"]["self-scan-pr"]["steps"] if s.get("id") == "self_scan")
    assert post["jobs"]["self-dep-scan"]["if"] == "github.event_name != 'push'"
    assert "schedule" in post[True] and "workflow_dispatch" in post[True]
    # Source analysis and release SBOMs are distinct evidence, retained on push.
    assert "if" not in post["jobs"]["self-sast-scan"]
    assert "if" not in post["jobs"]["generate-sbom"]


def test_superseding_main_keeps_paths_from_unverified_commits(tmp_path) -> None:
    import os
    import re
    import subprocess

    step = next(step for step in _ci()["jobs"]["changes"]["steps"] if step.get("id") == "classify")
    script = step["run"].replace("${{ github.event_name }}", "push")
    script = re.sub(r"\$\{\{.*?\}\}", "fixture-sha", script)
    # The immediately preceding push touched only docs; the last green ancestor
    # also includes an endpoint packaging edit whose run was superseded.
    script = (
        """
gh() { if [ "$API_FAIL" = 1 ]; then return 1; else printf '%s\\n' "$GREEN_SHA"; fi; }
git() {
  case "$1" in
    merge-base) test "$ANCESTOR" = 1 ;;
    diff) test "$3" = "$GREEN_SHA" && printf '%s\\n' README.md deploy/endpoints/linux/install.sh ;;
    ls-files)
      printf '%s\\n' README.md pyproject.toml ui/Dockerfile deploy/endpoints/linux/install.sh
      for ((i=0; i<5000; i++)); do printf 'unknown/long-path-to-force-a-full-pipe-%s.txt\\n' "$i"; done ;;
    *) return 1 ;;
  esac
}
"""
        + script
    )
    for api_fail, ancestor in [("0", "1"), ("1", "1"), ("0", "0")]:
        output = tmp_path / "output"
        output.write_text("")
        env = {
            **os.environ,
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            "GITHUB_SHA": "b" * 40,
            "GITHUB_REPOSITORY": "fixture/repo",
            "GREEN_SHA": "a" * 40,
            "API_FAIL": api_fail,
            "ANCESTOR": ancestor,
        }
        run = subprocess.run(["bash", "-c", script], cwd=ROOT, env=env, text=True, capture_output=True)
        assert run.returncode == 0, run.stderr
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert values["endpoint"] == "true"
        assert values["docs_only"] == "false"
        if api_fail == "1" or ancestor == "0":
            assert values["alpine_full"] == "true"
            assert values["full_python"] == "true"
            assert values["ui"] == "true"


def test_extras_audit_skips_only_proven_unchanged_dependency_inputs() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/extras-audit.yml").read_text())
    job = workflow["jobs"]["audit-extras"]
    assert job["needs"] == "changes"
    assert "github.event_name != 'pull_request'" in job["if"]
    assert "needs.changes.result != 'success'" in job["if"]
    assert "needs.changes.outputs.python_dependencies != 'false'" in job["if"]
    changes = workflow["jobs"]["changes"]
    assert any(s.get("with", {}).get("fetch-depth") == 0 for s in changes["steps"])
    script = next(s["run"] for s in changes["steps"] if s.get("id") == "classify")
    assert "git merge-base" in script
    assert "classify_ci_changes.py --base-ref" in script
    assert "--head-ref" in script
    assert "scripts/classify_ci_changes.py" in workflow[True]["pull_request"]["paths"]
    install = next(s["run"] for s in job["steps"] if s.get("name") == "Install selected extras")
    assert "uv sync --frozen" in install


UI_E2E_SHARDS = 4


def test_release_ui_context_aggregates_every_playwright_shard() -> None:
    """The required job name survives; the browser suite is split by --shard."""
    from scripts.check_release_main_ci import REQUIRED_UI_JOBS

    jobs = _ci()["jobs"]
    gate, shard, container = jobs["ui-e2e"], jobs["ui-e2e-shard"], jobs["ui-container-smoke"]
    assert gate["name"] == "UI E2E and container smoke"
    assert gate["name"] in REQUIRED_UI_JOBS
    assert {"changes", "ui-e2e-shard", "ui-e2e-smoke", "ui-container-smoke"} <= set(gate["needs"])
    assert "pull_request" not in shard["if"].replace("github.event_name != 'pull_request'", "")
    assert "needs.changes" not in shard["if"]
    assert container["if"].startswith(gate["if"].rstrip())
    assert shard["strategy"]["fail-fast"] is False
    assert shard["strategy"]["matrix"]["shard"] == list(range(1, UI_E2E_SHARDS + 1))
    assert shard["name"] == f"UI E2E shard (${{{{ matrix.shard }}}}/{UI_E2E_SHARDS})"
    e2e = next(step for step in shard["steps"] if step.get("name") == "UI E2E")
    assert e2e["run"].strip().endswith(f"npm run test:e2e -- --shard=${{{{ matrix.shard }}}}/{UI_E2E_SHARDS}")
    names = [step.get("name") for step in shard["steps"]]
    assert names.index("UI production build") < names.index("UI E2E")
    assert "UI container smoke test" not in names
    budget = next(step for step in shard["steps"] if step.get("name") == "UI bundle budget")
    assert budget["if"] == "matrix.shard == 1"
    assert [step.get("name") for step in container["steps"]].count("UI container smoke test") == 1


def test_ui_e2e_gate_fails_on_any_failed_or_missing_required_lane() -> None:
    import os
    import subprocess

    step = _ci()["jobs"]["ui-e2e"]["steps"][0]
    assert step["env"]["SHARD_RESULT"] == "${{ needs.ui-e2e-shard.result }}"
    assert step["env"]["SMOKE_RESULT"] == "${{ needs.ui-e2e-smoke.result }}"
    assert step["env"]["CONTAINER_RESULT"] == "${{ needs.ui-container-smoke.result }}"
    assert step["env"]["SHARD_REQUIRED"] == "${{ github.event_name != 'pull_request' }}"
    outcomes = ("success", "skipped", "failure", "cancelled")
    others = {"SHARD_RESULT": "skipped", "SHARD_REQUIRED": "false", "SMOKE_RESULT": "skipped", "SMOKE_REQUIRED": "false"}
    others |= {"CONTAINER_RESULT": "skipped", "CONTAINER_REQUIRED": "false"}
    for lane in ("SHARD", "SMOKE", "CONTAINER"):
        for required in ("true", "false", ""):
            for outcome in outcomes:
                env = {**os.environ, **others, f"{lane}_REQUIRED": required, f"{lane}_RESULT": outcome}
                passed = subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True).returncode == 0
                expected = outcome == "success" or (outcome == "skipped" and required == "false")
                assert passed == expected, (lane, required, outcome)


def test_container_smoke_condition_matches_the_gate_requirement() -> None:
    """The container job runs exactly when the gate requires its success."""
    from types import SimpleNamespace

    jobs = _ci()["jobs"]

    def _python(expression: str) -> str:
        expression = " ".join(expression.removeprefix("${{").removesuffix("}}").split()).replace("!cancelled()", "True")
        return expression.replace("&&", "and").replace("||", "or")

    runs = _python(jobs["ui-container-smoke"]["if"])
    gate_runs = _python(jobs["ui-e2e"]["if"])
    required = _python(jobs["ui-e2e"]["steps"][0]["env"]["CONTAINER_REQUIRED"])
    for event in ("pull_request", "push", "schedule", "workflow_dispatch", "merge_group"):
        for result in ("success", "failure", "skipped"):
            for ui in ("true", "false"):
                for container in ("true", "false", ""):
                    outputs = SimpleNamespace(ui=ui, ui_container=container)
                    context = {
                        "github": SimpleNamespace(event_name=event, ref="refs/heads/main"),
                        "needs": SimpleNamespace(changes=SimpleNamespace(result=result, outputs=outputs)),
                    }
                    scope = {"__builtins__": {}}
                    if eval(gate_runs, scope, context):
                        assert eval(runs, scope, context) == eval(required, scope, context), (event, result, ui, container)
                    else:
                        assert not eval(runs, scope, context)


def test_playwright_shards_partition_the_browser_suite_evenly() -> None:
    """The largest spec runs in parallel mode, so no shard holds one giant group."""
    spec = (ROOT / "ui" / "e2e" / "security-graph-cockpit.spec.ts").read_text(encoding="utf-8")
    assert 'test.describe.configure({ mode: "parallel" });' in spec


def test_lock_refresh_covers_the_python_sdk_lock() -> None:
    assert (ROOT / "sdks" / "python" / "uv.lock").is_file()
    lock_refresh = yaml.safe_load((ROOT / ".github" / "workflows" / "uv-lock-upgrade.yml").read_text())
    runs = "\n".join(step.get("run", "") for step in lock_refresh["jobs"]["upgrade"]["steps"])
    assert "uv lock --upgrade --project sdks/python" in runs
    assert "git add uv.lock sdks/python/uv.lock" in runs
