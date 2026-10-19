"""Execute monitor scripts against a fake GitHub API to verify quiet issue reuse."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node is required to execute GitHub Actions scripts")


def run_monitor(
    workflow,
    job,
    issues,
    *,
    fresh=False,
    latest_id=99,
    latest_attempt=1,
    main_sha="a" * 40,
    workflow_name="Publish to Registries",
    step_name=None,
    probe_env=None,
    history=("failure",) * 5,
    with_summary=False,
):
    data = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    script = next(
        step["with"]["script"]
        for step in data["jobs"][job]["steps"]
        if "github-script@" in step.get("uses", "") and (step_name is None or step.get("name") == step_name)
    )
    harness = """
    const fs = require('node:fs');
    const {script, issues, fresh, latest_id, latest_attempt, main_sha, workflow_name, probe_env, history} =
      JSON.parse(fs.readFileSync(0, 'utf8'));
    const events = [];
    const summary = [];
    const core = {summary: {addRaw(text) { summary.push(text); return this; }, write: async () => {}},
      warning: () => {}, notice: () => {}};
    const github = {paginate: async () => issues, rest: {
      actions: {listWorkflowRuns: async () => ({data: {workflow_runs: history.map((conclusion, i) => (
        i === 0 ? {id: latest_id, run_attempt: latest_attempt, status: 'completed', conclusion}
                : conclusion === 'in_progress'
                  ? {id: 1000 + i, run_attempt: 1, status: 'in_progress', conclusion: null}
                  : {id: 1000 + i, run_attempt: 1, status: 'completed', conclusion, head_sha: main_sha,
                     html_url: `https://github.com/run/${1000 + i}`}))}})},
      repos: {getBranch: async () => ({data: {commit: {sha: main_sha}}})},
      issues: {
      listForRepo: () => {}, createLabel: async () => {},
      create: async value => events.push({kind: 'create', ...value}),
      update: async value => events.push({kind: 'update', ...value}),
      createComment: async value => events.push({kind: 'comment', ...value}),
    }}};
    const context = {repo: {owner: 'owner', repo: 'repo'}, serverUrl: 'https://github.com', runId: 99,
      payload: {workflow_run: {id: 99, run_attempt: 1, workflow_id: 42, name: workflow_name, html_url: 'https://github.com/run/99',
        head_sha: 'a'.repeat(40), head_branch: 'main', conclusion: history[0], actor: {login: 'owner'}}}};
    process.env.REPORT = JSON.stringify({expected: '0.103.2', all_fresh: fresh, all_required_fresh: fresh, surfaces: []});
    Object.assign(process.env, probe_env || {});
    const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
    new AsyncFunction('github', 'context', 'core', script)(github, context, core)
      .then(() => console.log(JSON.stringify({events, summary: summary.join('')})))
      .catch(e => {console.error(e); process.exit(1)});
    """
    assert NODE is not None
    result = subprocess.run(
        [NODE, "-e", harness],
        input=json.dumps(
            {
                "script": script,
                "issues": issues,
                "fresh": fresh,
                "latest_id": latest_id,
                "latest_attempt": latest_attempt,
                "main_sha": main_sha,
                "workflow_name": workflow_name,
                "probe_env": probe_env,
                "history": list(history),
            }
        ),
        text=True,
        capture_output=True,
        check=True,
    )
    output = json.loads(result.stdout)
    return (output["events"], output["summary"]) if with_summary else output["events"]


@pytest.mark.parametrize(
    "workflow,job,title",
    [
        ("main-failure-alert.yml", "alert", "ci-regression: Publish to Registries failing on main"),
        ("surface-freshness.yml", "freshness", "supply-chain-drift: distribution surfaces out of sync"),
    ],
)
@pytest.mark.parametrize("state", ["open", "closed"])
def test_failure_reuses_tracker_without_repeat_comments(workflow, job, title, state):
    events = run_monitor(workflow, job, [{"number": 123, "title": title, "state": state}])
    assert len(events) == 1
    assert events[0]["kind"] == "update"
    assert events[0]["issue_number"] == 123
    assert events[0]["state"] == "open"


def test_surface_recovery_closes_tracker_without_extra_comment():
    title = "supply-chain-drift: distribution surfaces out of sync"
    events = run_monitor("surface-freshness.yml", "freshness", [{"number": 123, "title": title, "state": "open"}], fresh=True)
    assert len(events) == 1
    assert events[0]["kind"] == "update"
    assert events[0]["state"] == "closed"


CI_TITLE = "ci-regression: CI/CD Pipeline failing on main"


def _open_ci_issue():
    return [{"number": 5178, "title": CI_TITLE, "state": "open", "body": "Workflow **CI/CD Pipeline** failed on `main`."}]


def test_ci_recovery_closes_with_one_comment_naming_the_green_run():
    """Closing keeps the failure evidence in the body and cites the exact green run."""
    events = run_monitor(
        "main-failure-alert.yml", "resolve", _open_ci_issue(), workflow_name="CI/CD Pipeline", history=("success", "failure")
    )
    assert [e["kind"] for e in events] == ["comment", "update"]
    comment, close = events
    assert comment["issue_number"] == 5178
    assert "https://github.com/run/99" in comment["body"]
    assert "`aaaaaaa`" in comment["body"]
    assert "1 consecutive green run" in comment["body"]
    assert close["state"] == "closed" and close["state_reason"] == "completed"
    assert "body" not in close


def test_ci_recovery_is_a_noop_without_an_open_tracker():
    closed = [{**_open_ci_issue()[0], "state": "closed"}]
    for issues in ([], closed):
        assert run_monitor("main-failure-alert.yml", "resolve", issues, workflow_name="CI/CD Pipeline", history=("success",)) == []


@pytest.mark.parametrize(
    ("history", "closes"),
    [
        (("cancelled", "success", "failure"), True),
        (("cancelled", "in_progress", "success"), True),
        (("cancelled", "skipped", "success"), True),
        (("cancelled", "failure", "success"), False),
        (("cancelled", "timed_out"), False),
        (("cancelled",), False),
    ],
)
def test_cancelled_head_run_reconciles_from_the_newest_decisive_run(history, closes):
    """A cancelled run is not evidence; the newest completed green/red run decides."""
    events = run_monitor("main-failure-alert.yml", "resolve", _open_ci_issue(), workflow_name="CI/CD Pipeline", history=history)
    assert bool(events) is closes
    if closes:
        assert events[-1]["state"] == "closed"


def test_alert_and_resolve_trigger_on_every_decisive_conclusion():
    data = yaml.safe_load((ROOT / ".github/workflows/main-failure-alert.yml").read_text())
    alert_if = data["jobs"]["alert"]["if"]
    resolve_if = data["jobs"]["resolve"]["if"]
    for conclusion in ("failure", "timed_out", "startup_failure"):
        assert f'"{conclusion}"' in alert_if
    assert '"success"' in resolve_if and '"cancelled"' in resolve_if
    assert "head_branch == 'main'" in alert_if and "head_branch == 'main'" in resolve_if


def test_surface_verification_on_pr_branch_cannot_close_main_incident():
    data = yaml.safe_load((ROOT / ".github/workflows/surface-freshness.yml").read_text())
    step = next(s for s in data["jobs"]["freshness"]["steps"] if "github-script@" in s.get("uses", ""))
    assert "github.ref" in step["if"] and "github.event.repository.default_branch" in step["if"]


@pytest.mark.parametrize(
    "workflow,job,title",
    [
        ("main-failure-alert.yml", "alert", "ci-regression: Publish to Registries failing on main"),
        ("surface-freshness.yml", "freshness", "supply-chain-drift: distribution surfaces out of sync"),
    ],
)
def test_new_failures_still_alert_and_identical_reruns_are_noops(workflow, job, title):
    created = run_monitor(workflow, job, [])
    assert len(created) == 1 and created[0]["kind"] == "create"
    assert created[0]["title"] == title
    assert run_monitor(workflow, job, [{"number": 123, "title": title, "state": "open", "body": created[0]["body"]}]) == []


def test_surface_recovery_does_not_notify_again_after_closure():
    assert (
        run_monitor(
            "surface-freshness.yml",
            "freshness",
            [{"number": 123, "title": "supply-chain-drift: distribution surfaces out of sync", "state": "closed"}],
            fresh=True,
        )
        == []
    )


@pytest.mark.parametrize(
    "filename,job,upstream",
    [
        ("deployment-freshness.yml", "check", "Deploy MCP SSE"),
        ("surface-freshness.yml", "freshness", "Publish to Registries"),
    ],
)
def test_freshness_reconciles_after_success_and_failure(filename, job, upstream):
    data = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    trigger = data.get("on", data.get(True))
    assert upstream in trigger["workflow_run"]["workflows"]
    assert trigger["workflow_run"]["types"] == ["completed"]
    condition = data["jobs"][job]["if"]
    assert '["success","failure"]' in condition


@pytest.mark.parametrize("job", ["alert", "resolve"])
@pytest.mark.parametrize("latest", [{"latest_id": 100}, {"latest_attempt": 2}])
def test_obsolete_completion_cannot_change_regression_tracker(job, latest):
    issues = [{"number": 123, "title": "ci-regression: Publish to Registries failing on main", "state": "open"}]
    assert run_monitor("main-failure-alert.yml", job, issues, **latest) == []


@pytest.mark.parametrize("job", ["alert", "resolve"])
def test_ci_completion_for_old_main_sha_cannot_change_tracker(job):
    issues = [{"number": 123, "title": "ci-regression: CI/CD Pipeline failing on main", "state": "open"}]
    assert run_monitor("main-failure-alert.yml", job, issues, workflow_name="CI/CD Pipeline", main_sha="b" * 40) == []


DEPLOYMENT_STEP = "Reconcile deployment monitoring issues"
DEPLOYMENT_TITLE = "supply-chain-drift: deployment surfaces out of sync"
UNMONITORED_TITLE = "deployment-monitoring: a deployment surface is UNMONITORED (missing config)"


def run_deployment(issues, **overrides):
    env = {
        "EXPECTED_VERSION": "0.105.0",
        "RAILWAY_VERSION": "unreachable",
        "RAILWAY_OUTCOME": "success",
        "RAILWAY_PROBE_FAILED": "true",
        "PUBLIC_VERSION": "fresh",
        "PUBLIC_OUTCOME": "success",
        "PUBLIC_NOT_CONFIGURED": "false",
        "RAILWAY_TOOLS": "unknown",
        "PUBLIC_TOOLS": "8",
    }
    env.update(overrides)
    return run_monitor("deployment-freshness.yml", "check", issues, step_name=DEPLOYMENT_STEP, probe_env=env)


@pytest.mark.parametrize("title", [DEPLOYMENT_TITLE, UNMONITORED_TITLE])
def test_deployment_reopens_completed_tracker_and_never_comments(title):
    issue = {"number": 5270, "title": title, "state": "closed", "state_reason": "completed"}
    env = {"PUBLIC_NOT_CONFIGURED": "true"} if title == UNMONITORED_TITLE else {}
    if title == UNMONITORED_TITLE:
        env.update(RAILWAY_VERSION="0.105.0", RAILWAY_PROBE_FAILED="false")
    events = run_deployment([issue], **env)
    assert len(events) == 1 and events[0]["kind"] == "update"
    assert events[0]["issue_number"] == 5270 and events[0]["state"] == "open"
    assert run_deployment([{**issue, "state": "open", "body": events[0]["body"]}], **env) == []


def test_deployment_ignores_closed_duplicate_and_pull_requests():
    issues = [
        {"number": 5339, "title": DEPLOYMENT_TITLE, "state": "closed", "state_reason": "not_planned"},
        {"number": 5340, "title": DEPLOYMENT_TITLE, "state": "open", "pull_request": {}},
        {"number": 5270, "title": DEPLOYMENT_TITLE, "state": "closed", "state_reason": "completed"},
    ]
    assert run_deployment(issues)[0]["issue_number"] == 5270


@pytest.mark.parametrize(
    "field,value", [("EXPECTED_VERSION", ""), ("RAILWAY_OUTCOME", "failure"), ("RAILWAY_PROBE_FAILED", ""), ("RAILWAY_VERSION", "0.104.0")]
)
def test_deployment_never_closes_without_verified_success(field, value):
    issue = {"number": 5270, "title": DEPLOYMENT_TITLE, "state": "open"}
    env = {"RAILWAY_VERSION": "0.105.0", "RAILWAY_PROBE_FAILED": "false", field: value}
    assert not any(e.get("state") == "closed" for e in run_deployment([issue], **env))


def test_deployment_recovery_is_quiet_and_preserves_distribution_tracker():
    issues = [
        {"number": 5270, "title": DEPLOYMENT_TITLE + " with 0.104.0", "state": "open"},
        {"number": 5184, "title": "supply-chain-drift: distribution surfaces out of sync", "state": "open"},
        {"number": 12, "title": UNMONITORED_TITLE, "state": "open"},
    ]
    events = run_deployment(issues, RAILWAY_VERSION="0.105.0", RAILWAY_PROBE_FAILED="false")
    assert {e["issue_number"] for e in events} == {5270, 12}
    assert all(e["kind"] == "update" and e["state"] == "closed" for e in events)


def test_deployment_missing_public_probe_cannot_close_unmonitored_tracker():
    issue = {"number": 12, "title": UNMONITORED_TITLE, "state": "open"}
    events = run_deployment([issue], RAILWAY_VERSION="0.105.0", RAILWAY_PROBE_FAILED="false", PUBLIC_VERSION="", PUBLIC_OUTCOME="skipped")
    assert events == []


def test_deployment_issue_mutation_is_default_branch_only():
    data = yaml.safe_load((ROOT / ".github/workflows/deployment-freshness.yml").read_text())
    steps = [s for s in data["jobs"]["check"]["steps"] if "github-script@" in s.get("uses", "")]
    assert steps
    for step in steps:
        assert "github.ref" in step["if"] and "github.event.repository.default_branch" in step["if"]


@pytest.mark.parametrize(
    "workflow,job,title",
    [
        ("main-failure-alert.yml", "alert", "ci-regression: Publish to Registries failing on main"),
        ("surface-freshness.yml", "freshness", "supply-chain-drift: distribution surfaces out of sync"),
    ],
)
def test_same_failure_from_a_different_run_does_not_update_issue(workflow, job, title):
    created = run_monitor(workflow, job, [])[0]
    previous_body = created["body"].replace("/99", "/98").replace("- Actor: @owner", "- Actor: @previous-owner")
    issue = {"number": 123, "title": title, "state": "open", "body": previous_body}
    assert run_monitor(workflow, job, [issue]) == []


@pytest.mark.parametrize(
    "workflow,job,title,old,new",
    [
        ("main-failure-alert.yml", "alert", "ci-regression: Publish to Registries failing on main", "aaaaaaa", "bbbbbbb"),
        ("surface-freshness.yml", "freshness", "supply-chain-drift: distribution surfaces out of sync", "0.103.2", "0.103.1"),
    ],
)
def test_changed_failure_evidence_still_updates_issue(workflow, job, title, old, new):
    created = run_monitor(workflow, job, [])[0]
    issue = {"number": 123, "title": title, "state": "open", "body": created["body"].replace(old, new)}
    events = run_monitor(workflow, job, [issue])
    assert len(events) == 1 and events[0]["kind"] == "update"


@pytest.mark.parametrize(
    ("history", "alerts"),
    [
        (("failure",), False),
        (("failure", "success", "failure", "failure"), False),
        (("failure", "failure", "success"), False),
        (("failure", "failure", "failure"), True),
        (("failure", "cancelled", "failure", "skipped", "failure"), True),
        (("timed_out", "failure", "startup_failure"), True),
        (("failure", "in_progress", "failure", "failure"), True),
    ],
)
def test_regression_issue_opens_only_after_consecutive_main_failures(history, alerts):
    """A single red run on main is noise; three in a row is an incident."""
    events = run_monitor(
        "main-failure-alert.yml",
        "alert",
        [],
        workflow_name="CI/CD Pipeline",
        history=history,
    )

    assert bool(events) is alerts
    if alerts:
        assert events[0]["kind"] == "create"
        assert "3 consecutive failed runs" in events[0]["body"]


def _freshness_report(status):
    return json.dumps(
        {
            "expected": "0.106.1",
            "all_fresh": False,
            "all_required_fresh": False,
            "surfaces": [
                {"surface": "PyPI", "status": "fresh", "required": True},
                {"surface": "Glama", "status": status, "required": True},
            ],
        }
    )


@pytest.mark.parametrize(
    ("status", "release_age_hours", "alerts"),
    [
        ("stale", 2, False),
        ("stale", 47, False),
        ("stale", 48, True),
        ("stale", 72, True),
        ("unreachable", 2, True),
        ("unmonitored (misconfigured)", 2, True),
    ],
)
def test_freshness_waits_out_registry_sync_after_a_release(status, release_age_hours, alerts):
    """A registry one version behind right after a release is sync lag, not drift."""
    from datetime import datetime, timedelta, timezone

    published_at = (datetime.now(timezone.utc) - timedelta(hours=release_age_hours)).isoformat()
    events = run_monitor(
        "surface-freshness.yml",
        "freshness",
        [],
        probe_env={"REPORT": _freshness_report(status), "RELEASE_PUBLISHED_AT": published_at},
    )

    assert bool(events) is alerts


@pytest.mark.parametrize(
    ("failures", "alerts"),
    [(3, False), (4, False), (5, True)],
)
def test_scheduled_publish_workflows_need_a_longer_failure_streak(failures, alerts):
    """Registry publishing retries while providers sync; four red runs are still sync lag."""
    events = run_monitor(
        "main-failure-alert.yml",
        "alert",
        [],
        workflow_name="Publish to Registries",
        history=("failure",) * failures,
    )

    assert bool(events) is alerts


def test_open_freshness_tracker_updates_during_sync_grace_without_repeat_comments():
    from datetime import datetime, timedelta, timezone

    issue = {
        "number": 5184,
        "title": "supply-chain-drift: distribution surfaces out of sync",
        "state": "open",
        "body": "Previous release: Glama probe timed out",
    }
    report = json.loads(_freshness_report("stale"))
    report["surfaces"][1]["error"] = "input schema differs for tool: exposure_paths"
    env = {
        "REPORT": json.dumps(report),
        "RELEASE_PUBLISHED_AT": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    }
    events = run_monitor("surface-freshness.yml", "freshness", [issue], probe_env=env)
    assert len(events) == 1
    update = events[0]
    assert (update["kind"], update["issue_number"], update["state"]) == ("update", 5184, "open")
    assert "input schema differs for tool: exposure_paths" in update["body"]
    assert "0.106.1" in update["body"]
    assert run_monitor("surface-freshness.yml", "freshness", [{**issue, "body": update["body"]}], probe_env=env) == []


def test_closed_freshness_tracker_stays_closed_during_sync_grace():
    from datetime import datetime, timedelta, timezone

    issue = {"number": 5184, "title": "supply-chain-drift: distribution surfaces out of sync", "state": "closed"}
    env = {
        "REPORT": _freshness_report("stale"),
        "RELEASE_PUBLISHED_AT": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    }
    assert run_monitor("surface-freshness.yml", "freshness", [issue], probe_env=env) == []


def _partial_glama_report(*, api_status="empty", extra_surfaces=()):
    report = json.loads(_freshness_report("fresh_degraded"))
    report["surfaces"][1].update(
        version="0.106.1",
        expected="0.106.1",
        error=None,
        degraded_reason=f"Glama Directory API inventory is {api_status}; using public Schema page evidence",
        directory_api={"status": api_status, "tool_count": 0},
        exact_tool_set=True,
        exact_input_schemas=True,
    )
    report["surfaces"].extend(extra_surfaces)
    return {"REPORT": json.dumps(report)}


PENDING_TITLE = "supply-chain-drift: distribution verification incomplete"


@pytest.mark.parametrize("issues", [[], [{"number": 5184, "title": PENDING_TITLE, "state": "closed"}]])
def test_pending_external_verification_never_opens_or_reopens_a_tracker(issues):
    """Provider-side evidence gaps are a status, not an incident that reopens every run."""
    events, summary = run_monitor("surface-freshness.yml", "freshness", issues, probe_env=_partial_glama_report(), with_summary=True)
    assert events == []
    assert "External verification pending" in summary
    assert "Glama Directory API inventory is empty" in summary
    assert "No distribution drift" in summary


def test_open_tracker_with_only_pending_external_verification_is_closed_once():
    issue = {"number": 5184, "title": "supply-chain-drift: distribution verification incomplete", "state": "open"}
    events = run_monitor("surface-freshness.yml", "freshness", [issue], probe_env=_partial_glama_report())
    assert len(events) == 1
    close = events[0]
    assert (close["kind"], close["issue_number"], close["state"]) == ("update", 5184, "closed")
    assert close["state_reason"] == "not_planned"
    assert "Glama Directory API inventory is empty" in close["body"]
    assert "external" in close["body"].lower()
    assert "reopens" in close["body"].lower()
    # The next identical probe sees a closed tracker and stays silent.
    assert run_monitor("surface-freshness.yml", "freshness", [{**issue, **close}], probe_env=_partial_glama_report()) == []


def test_pending_external_verification_does_not_suppress_real_drift():
    stale_docker = {"surface": "Docker", "status": "stale", "version": "0.106.0", "expected": "0.106.1", "required": True}
    env = _partial_glama_report(extra_surfaces=[stale_docker])
    env["RELEASE_PUBLISHED_AT"] = "2020-01-01T00:00:00Z"
    events, summary = run_monitor("surface-freshness.yml", "freshness", [], probe_env=env, with_summary=True)
    assert len(events) == 1 and events[0]["kind"] == "create"
    assert events[0]["title"] == "supply-chain-drift: distribution surfaces out of sync"
    assert "Docker" in events[0]["body"] and "STALE" in events[0]["body"]
    assert "Distribution drift detected" in summary


@pytest.mark.parametrize("status", ["stale", "unreachable", "not_configured"])
def test_actual_drift_after_partial_evidence_keeps_the_same_tracker(status):
    issue = {"number": 5184, "title": "supply-chain-drift: distribution verification incomplete", "state": "open"}
    env = _partial_glama_report(extra_surfaces=[{"surface": "Docker", "status": status, "required": True}])
    events = run_monitor("surface-freshness.yml", "freshness", [issue], probe_env=env)
    assert len(events) == 1
    assert events[0]["kind"] == "update" and events[0]["issue_number"] == 5184
    assert events[0]["title"] == "supply-chain-drift: distribution surfaces out of sync"


def test_full_recovery_closes_the_renamed_partial_evidence_tracker():
    issue = {"number": 5184, "title": "supply-chain-drift: distribution verification incomplete", "state": "open"}
    events = run_monitor("surface-freshness.yml", "freshness", [issue], fresh=True)
    assert len(events) == 1 and events[0]["issue_number"] == 5184
    assert events[0]["state"] == "closed"


def test_partial_evidence_detail_escapes_markdown_table_delimiters():
    env = _partial_glama_report(api_status="empty|unknown\nretry")
    _, summary = run_monitor("surface-freshness.yml", "freshness", [], probe_env=env, with_summary=True)
    assert "empty\\|unknown<br>retry" in summary
