"""Current-evidence changes retain every split lifecycle contract."""

from pathlib import Path

from scripts.pytest_ci_plan import select_targeted_tests


def test_current_evidence_changes_select_all_lifecycle_splits(tmp_path: Path) -> None:
    modules = {tmp_path / f"tests/test_demo_estate_bootstrap_{part}.py" for part in ("lifecycle", "restart", "refresh")}
    for module in modules:
        module.parent.mkdir(exist_ok=True)
        module.write_text("")
    selected = select_targeted_tests(changed_files=[Path("src/agent_bom/api/stores.py")], root=tmp_path)
    assert modules <= set(selected)
