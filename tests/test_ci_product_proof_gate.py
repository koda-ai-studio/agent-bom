"""Product captures are required CI evidence and cannot publish from a PR."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _jobs():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]


def test_product_proof_runs_beside_ui_checks_with_read_only_permissions():
    jobs = _jobs()
    assert "ui-product-proof" in jobs, "UI changes need a pre-merge product capture"
    proof = jobs["ui-product-proof"]
    assert proof["needs"] == "changes"
    assert proof["if"] == jobs["ui"]["if"]
    assert proof["permissions"] == {"contents": "read"}
    assert proof["timeout-minutes"] <= 10, "the capture runs beside the E2E shards; a longer limit hides a hang"
    assert not proof.get("continue-on-error")
    commands = "\n".join(step.get("run", "") for step in proof["steps"])
    assert "npm run capture:product-proof" in commands
    assert commands.index("npm run build") < commands.index("npm run capture:product-proof")
    assert "playwright install --with-deps chromium" in commands
    assert 'PYTHON="$GITHUB_WORKSPACE/.venv/bin/python"' in commands
    assert not any(word in commands for word in ("git push", "git commit", "npm publish", "gh release"))
    assert not any(step.get("continue-on-error") for step in proof["steps"])


@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped"])
def test_required_ui_gate_rejects_missing_or_failed_product_proof(result):
    gate = _jobs()["ui-e2e"]
    assert "ui-product-proof" in gate["needs"]
    step = gate["steps"][0]
    assert step["env"]["PROOF_RESULT"] == "${{ needs.ui-product-proof.result }}"
    assert step["env"]["PROOF_REQUIRED"] == "true"
    env = {**os.environ, "PROOF_RESULT": result, "PROOF_REQUIRED": "true"}
    for lane in ("SHARD", "SMOKE", "CONTAINER"):
        env.update({f"{lane}_RESULT": "success", f"{lane}_REQUIRED": "true"})
    checked = subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True, timeout=5)
    assert (checked.returncode == 0) is (result == "success"), checked.stdout + checked.stderr
