"""OCSF helper edits must exercise the exact analytics/tenant ingest contract."""

from pathlib import Path

import pytest

from scripts.pytest_ci_plan import select_targeted_tests


@pytest.mark.parametrize("source", ["ocsf_fields.py", "observability_events.py", "routes/observability.py"])
def test_ocsf_edits_select_analytics_contract(tmp_path, source):
    contract = tmp_path / "tests/api/test_api_tenant_isolation.py"
    contract.parent.mkdir(parents=True)
    contract.write_text("pass\n")
    assert contract in select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path)
