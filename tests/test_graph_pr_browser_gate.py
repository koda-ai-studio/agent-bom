"""Graph readability regressions must be checked before merge."""

from pathlib import Path

import yaml


def test_pr_browser_smoke_includes_complete_graph_readability_suite() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["ui-e2e-smoke"]
    step = next(step for step in job["steps"] if step.get("name") == "UI E2E smoke")
    command = step["run"]
    assert "e2e/lineage-graph-readability.spec.ts" in command
    assert "--grep" not in command
    assert "--pass-with-no-tests" not in command
    assert not step.get("continue-on-error", False)
