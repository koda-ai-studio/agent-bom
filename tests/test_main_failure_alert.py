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
