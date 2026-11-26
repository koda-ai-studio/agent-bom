"""Workflow install security contracts must run before entering the merge queue."""

from pathlib import Path

import pytest

from scripts.pytest_ci_plan import select_targeted_tests


@pytest.mark.parametrize("source", ["dockerhub-cleanup.yml", "new-workflow.yml", "removed-workflow.yaml"])
def test_workflow_edits_select_installer_security_floor(tmp_path: Path, source: str) -> None:
    contracts = [tmp_path / "tests" / name for name in ("test_deployment.py", "test_ca_incident_tool_floors.py")]
    for path in [*contracts, tmp_path / "tests/test_unrelated.py"]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n")
    assert set(select_targeted_tests(changed_files=[Path(".github/workflows") / source], root=tmp_path)) == set(contracts)
