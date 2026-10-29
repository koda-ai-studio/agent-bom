"""The PR affected-test selection: changed-domain mapping plus direct importers."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.pytest_ci_affected import select_affected_tests
from scripts.pytest_ci_plan import select_targeted_tests

ROOT = Path(__file__).resolve().parents[1]


def test_contract_smoke_always_checks_the_line_ceiling_baseline() -> None:
    from scripts.pytest_ci_affected import SMOKE_TESTS

    assert "tests/test_check_line_ceiling.py" in SMOKE_TESTS


def _write(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _source(root: Path, rel: str) -> Path:
    return _write(root / rel, "VALUE = 1\n")


def test_affected_keeps_every_changed_domain_selection(tmp_path: Path) -> None:
    _source(tmp_path, "src/agent_bom/widget.py")
    mapped = _write(tmp_path / "tests/test_widget.py")
    _write(tmp_path / "tests/test_unrelated.py")
    changed = [Path("src/agent_bom/widget.py")]
    assert set(select_targeted_tests(changed_files=changed, root=tmp_path)) <= set(
        select_affected_tests(changed_files=changed, root=tmp_path)
    )
    assert select_affected_tests(changed_files=changed, root=tmp_path) == [mapped]


@pytest.mark.parametrize(
    "statement",
    [
        "from agent_bom.core.helpers import thing\n",
        "import agent_bom.core.helpers\n",
        "from agent_bom.core import helpers\n",
        "from agent_bom.core import (\n    other,\n    helpers,\n)\n",
        'monkeypatch.setattr("agent_bom.core.helpers.thing", 1)\n',
    ],
)
def test_shared_module_selects_tests_that_import_it(tmp_path: Path, statement: str) -> None:
    """A shared input without a basename test still selects its direct importers."""
    _source(tmp_path, "src/agent_bom/core/helpers.py")
    importer = _write(tmp_path / "tests/api/test_consumer.py", statement)
    _write(tmp_path / "tests/test_unrelated.py", "from agent_bom.core.helpers_extra import x\nimport agent_bom.core\n")
    assert select_affected_tests(changed_files=[Path("src/agent_bom/core/helpers.py")], root=tmp_path) == [importer]


def test_package_init_selects_tests_importing_the_package(tmp_path: Path) -> None:
    _source(tmp_path, "src/agent_bom/graph/__init__.py")
    importer = _write(tmp_path / "tests/test_graph_user.py", "from agent_bom.graph import Edge\n")
    _write(tmp_path / "tests/test_submodule_only.py", "from agent_bom.graph.edge import Edge\n")
    assert select_affected_tests(changed_files=[Path("src/agent_bom/graph/__init__.py")], root=tmp_path) == [importer]


def test_script_changes_select_tests_that_load_the_script(tmp_path: Path) -> None:
    _source(tmp_path, "scripts/check_thing.py")
    loader = _write(tmp_path / "tests/test_loader.py", 'SCRIPT = ROOT / "scripts" / "check_thing.py"\n')
    importer = _write(tmp_path / "tests/test_importer.py", "from scripts.check_thing import main\n")
    _write(tmp_path / "tests/test_unrelated.py", "check_thing_extra = 1\n")
    assert select_affected_tests(changed_files=[Path("scripts/check_thing.py")], root=tmp_path) == [importer, loader]


def test_conftest_selects_every_test_below_its_directory(tmp_path: Path) -> None:
    _write(tmp_path / "tests/api/conftest.py")
    inside = [_write(tmp_path / "tests/api/test_one.py"), _write(tmp_path / "tests/api/nested/test_two.py")]
    _write(tmp_path / "tests/test_outside.py")
    assert select_affected_tests(changed_files=[Path("tests/api/conftest.py")], root=tmp_path) == sorted(inside)


def test_test_helper_module_selects_its_importers(tmp_path: Path) -> None:
    _write(tmp_path / "tests/_estate_helpers.py")
    user = _write(tmp_path / "tests/test_user.py", "from tests._estate_helpers import seed\n")
    _write(tmp_path / "tests/test_other.py")
    assert select_affected_tests(changed_files=[Path("tests/_estate_helpers.py")], root=tmp_path) == [user]


def test_fixture_data_selects_tests_that_reference_it(tmp_path: Path) -> None:
    _write(tmp_path / "tests/fixtures/sboms/sample-app.cdx.json")
    by_file = _write(tmp_path / "tests/test_by_file.py", 'FIXTURE = FIXTURES / "sboms" / "sample-app.cdx.json"\n')
    by_dir = _write(tmp_path / "tests/test_by_dir.py", 'CORPUS = FIXTURES / "sboms"\n')
    _write(tmp_path / "tests/test_other.py", "sboms_count = 3\n")
    changed = [Path("tests/fixtures/sboms/sample-app.cdx.json")]
    assert select_affected_tests(changed_files=changed, root=tmp_path) == [by_dir, by_file]


def test_deleted_source_still_selects_its_former_importers(tmp_path: Path) -> None:
    importer = _write(tmp_path / "tests/test_consumer.py", "from agent_bom.retired import thing\n")
    assert select_affected_tests(changed_files=[Path("src/agent_bom/retired.py")], root=tmp_path) == [importer]


def test_non_python_inputs_add_nothing_beyond_the_domain_map(tmp_path: Path) -> None:
    _write(tmp_path / "tests/test_anything.py", "README = 1\n")
    for changed in ("README.md", "ui/app/page.tsx", "uv.lock"):
        assert select_affected_tests(changed_files=[Path(changed)], root=tmp_path) == select_targeted_tests(
            changed_files=[Path(changed)], root=tmp_path
        )


def test_cli_prints_repository_relative_selection(tmp_path: Path) -> None:
    _source(tmp_path, "src/agent_bom/core/helpers.py")
    _write(tmp_path / "tests/test_consumer.py", "from agent_bom.core.helpers import thing\n")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/pytest_ci_affected.py"), "--root", ".", "src/agent_bom/core/helpers.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.splitlines() == ["tests/test_consumer.py"]


def test_real_shared_inputs_select_their_importers() -> None:
    """Inputs that used to force the full suite now select real consumers, not just smoke."""
    for shared in ("src/agent_bom/models.py", "src/agent_bom/graph/correlation.py", "src/agent_bom/security.py"):
        selected = select_affected_tests(changed_files=[Path(shared)], root=ROOT)
        targeted = select_targeted_tests(changed_files=[Path(shared)], root=ROOT)
        assert len(selected) > len(targeted), shared


def test_duration_budget_expands_shards_without_dropping_tests(tmp_path: Path) -> None:
    from scripts.pytest_ci_affected import affected_shard_count
    from scripts.pytest_ci_plan import plan_shards

    files = [_write(tmp_path / f"tests/test_case_{i}.py") for i in range(24)]
    durations = dict.fromkeys(files, 300.0)
    count = affected_shard_count(files, durations=durations, target_seconds=900)
    assert count == 8
    shards = plan_shards(files, total=count, durations=durations)
    assert sorted(path for shard in shards for path in shard) == sorted(files)
    assert all(sum(durations[path] for path in shard) <= 900 for shard in shards)


def test_affected_shards_are_bounded_and_never_empty(tmp_path: Path) -> None:
    from scripts.pytest_ci_affected import affected_shard_count

    files = [_write(tmp_path / f"tests/test_case_{i}.py") for i in range(12)]
    assert affected_shard_count(files, durations=dict.fromkeys(files, 1.0)) == 1
    assert affected_shard_count(files, durations=dict.fromkeys(files, 10000.0)) == 12
    assert affected_shard_count(files[:2], durations={}) == 2
    assert affected_shard_count(files, durations={}) == 12
    with pytest.raises(ValueError, match="empty"):
        affected_shard_count([], durations={})


def test_partial_timings_estimate_unknown_modules(tmp_path: Path) -> None:
    from scripts.pytest_ci_affected import affected_shard_count

    files = [_write(tmp_path / f"tests/test_case_{i}.py") for i in range(8)]
    assert affected_shard_count(files, durations={files[0]: 300.0}, target_seconds=600) == 4


def test_cli_matrix_and_selection_include_identical_contracts(tmp_path: Path) -> None:
    import json

    from scripts.pytest_ci_affected import SMOKE_TESTS

    for name in SMOKE_TESTS:
        _write(tmp_path / name)
    command = [sys.executable, str(ROOT / "scripts/pytest_ci_affected.py"), "--root", ".", "--include-smoke"]
    selection = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=True)
    matrix = subprocess.run([*command, "--matrix"], cwd=tmp_path, capture_output=True, text=True, check=True)
    assert selection.stdout.splitlines() == sorted(SMOKE_TESTS)
    assert json.loads(matrix.stdout) == list(range(12))
