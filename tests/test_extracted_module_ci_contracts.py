"""Extracted implementations must retain the owning surface's CI coverage."""

from pathlib import Path

import pytest

from scripts.pytest_ci_plan import select_targeted_tests


@pytest.mark.parametrize(
    ("source", "contract"),
    [
        ("core/security_validation.py", "test_security.py"),
        ("api/identity_models.py", "test_agent_identity_lifecycle.py"),
        ("api/identity_local_store.py", "test_identity_policy_tenant_boundary.py"),
        ("cli/_server_posture.py", "test_cli_serve_auth_enforce.py"),
        ("output/json_inventory.py", "test_evidence_portability.py"),
    ],
)
def test_extracted_owner_selects_behavior_contract(tmp_path: Path, source: str, contract: str) -> None:
    expected = tmp_path / "tests" / contract
    expected.parent.mkdir()
    expected.write_text("")
    assert expected in select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path)
