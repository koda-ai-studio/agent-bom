"""Execute the alert workflow against organization-owned repository fixtures."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_regression_creates_blocker_without_assigning_organization() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the GitHub Actions script")
    workflow = yaml.safe_load((ROOT / ".github/workflows/main-failure-alert.yml").read_text())
    script = workflow["jobs"]["alert"]["steps"][0]["with"]["script"]
    harness = r"""
const assert = require('node:assert/strict');
const run = {id: 10, run_attempt: 1, workflow_id: 42, name: 'Runtime Helm Acceptance',
  head_sha: 'a'.repeat(40), html_url: 'https://github.com/example/repo/actions/runs/10',
  actor: {login: 'maintainer'}, status: 'completed', conclusion: 'failure'};
const context = {repo: {owner: 'example-org', repo: 'repo'},
  serverUrl: 'https://github.com', payload: {workflow_run: run}};
let created;
const github = {rest: {actions: {listWorkflowRuns: async () => ({data: {
  workflow_runs: Array.from({length: 6}, (_, index) => ({...run, id: 10 - index}))
}})}, issues: {listForRepo: () => {}, create: async args => {
  assert.ok(!args.assignees?.includes(context.repo.owner), 'organization cannot be an issue assignee');
  created = args;
}}}, paginate: async () => []};
const execute = new Function('github', 'context', 'return (async () => {' + SCRIPT + '})()');
execute(github, context).then(() => {
  assert.ok(created, 'the regression must create an issue');
  assert.deepEqual(created.labels, ['ci-regression', 'release-blocker']);
  assert.ok(created.body.includes(run.html_url), 'failure evidence must be retained');
}).catch(error => {console.error(error.message); process.exitCode = 1;});
"""
    result = subprocess.run(
        [node, "-e", "const SCRIPT = " + json.dumps(script) + ";\n" + harness], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("job", ["alert", "resolve"])
def test_only_main_pushes_from_this_repository_drive_alerts(job: str) -> None:
    """A fork or pull-request run whose head branch is named main must not open or close the blocker.

    CI's nightly run is the only other lane: it carries the four-interpreter
    suite that main pushes no longer run.
    """
    workflow = yaml.safe_load((ROOT / ".github/workflows/main-failure-alert.yml").read_text())
    condition = workflow["jobs"][job]["if"]
    assert (
        "(github.event.workflow_run.event == 'push' || (github.event.workflow_run.event == 'schedule' && "
        "github.event.workflow_run.name == 'CI/CD Pipeline'))"
    ) in condition
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in condition
    script = workflow["jobs"][job]["steps"][0]["with"]["script"]
    assert 'branch: "main", event: lane' in script
    assert 'const lane = context.payload.workflow_run.event === "schedule" ? "schedule" : "push";' in script


_LANE_HARNESS = r"""
const assert = require('node:assert/strict');
const [event, failures, headMoved, existingTitle] = JSON.parse(process.argv[1]);
const run = {id: 10, run_attempt: 1, workflow_id: 42, name: 'CI/CD Pipeline', event,
  head_sha: 'a'.repeat(40), html_url: 'https://github.com/example/repo/actions/runs/10',
  actor: {login: 'maintainer'}, status: 'completed', conclusion: failures ? 'failure' : 'success'};
const context = {repo: {owner: 'example-org', repo: 'repo'}, serverUrl: 'https://github.com', payload: {workflow_run: run}};
const result = {created: null, closed: null, listed: null};
const history = Array.from({length: 6}, (_, index) => ({...run, id: 10 - index,
  conclusion: index < Math.max(failures, 1) ? run.conclusion : (failures ? 'success' : 'failure')}));
const github = {rest: {
  actions: {listWorkflowRuns: async args => { result.listed = args.event; return {data: {workflow_runs: history}}; }},
  repos: {getBranch: async () => ({data: {commit: {sha: headMoved ? 'b'.repeat(40) : run.head_sha}}})},
  issues: {listForRepo: () => {}, create: async args => { result.created = args.title; },
    createComment: async () => {}, update: async args => { result.closed = args.issue_number; }}},
  paginate: async () => existingTitle ? [{number: 7, title: existingTitle, state: 'open', body: ''}] : []};
const execute = new Function('github', 'context', 'return (async () => {' + SCRIPT + '})()');
execute(github, context).then(() => console.log(JSON.stringify(result)))
  .catch(error => {console.error(error.message); process.exitCode = 1;});
"""


def _lane(job: str, event: str, failures: int, *, head_moved: bool = False, existing: str = "") -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the GitHub Actions script")
    workflow = yaml.safe_load((ROOT / ".github/workflows/main-failure-alert.yml").read_text())
    script = workflow["jobs"][job]["steps"][0]["with"]["script"]
    args = json.dumps([event, failures, head_moved, existing])
    result = subprocess.run(
        [node, "-e", "const SCRIPT = " + json.dumps(script) + ";\n" + _LANE_HARNESS, args], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_nightly_ci_failures_open_their_own_blocker_after_two_nights() -> None:
    assert _lane("alert", "schedule", 1)["created"] is None
    outcome = _lane("alert", "schedule", 2, head_moved=True)
    assert outcome["listed"] == "schedule"
    assert outcome["created"] == "ci-regression: CI/CD Pipeline nightly failing on main"
    push = _lane("alert", "push", 3)
    assert push["listed"] == "push"
    assert push["created"] == "ci-regression: CI/CD Pipeline failing on main"


def test_a_green_push_cannot_clear_a_red_nightly_lane() -> None:
    nightly = "ci-regression: CI/CD Pipeline nightly failing on main"
    assert _lane("resolve", "push", 0, existing=nightly)["closed"] is None
    # A green night closes its own tracker even after main moved on.
    assert _lane("resolve", "schedule", 0, head_moved=True, existing=nightly)["closed"] == 7
    assert _lane("resolve", "schedule", 0, existing="ci-regression: CI/CD Pipeline failing on main")["closed"] is None
