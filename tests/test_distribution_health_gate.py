"""Successful probes must not hide unhealthy required distributions."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_freshness_preserves_evidence_and_issues_before_failing_health():
    workflow = yaml.safe_load((ROOT / ".github/workflows/surface-freshness.yml").read_text())
    steps = workflow["jobs"]["freshness"]["steps"]
    probe = next(step for step in steps if step.get("id") == "probe")
    assert "--fail-on-stale" in probe["run"]
    assert probe.get("continue-on-error") is True
    assert 'exit "$probe_exit"' in probe["run"]
    assert probe["run"].index("cat surface-freshness.json") < probe["run"].index('exit "$probe_exit"')
    gate = steps[-1]
    assert gate["name"] == "Enforce required distribution health"
    assert gate["if"] == "always()" and gate.get("continue-on-error") is not True
    assert gate["env"]["PROBE_OUTCOME"] == "${{ steps.probe.outcome }}"
    assert 'test "$PROBE_OUTCOME" = success' in gate["run"]
    assert any(step.get("if") == "always()" and "upload-artifact" in step.get("uses", "") for step in steps[:-1])
