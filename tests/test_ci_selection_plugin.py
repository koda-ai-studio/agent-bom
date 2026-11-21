"""A shard collected from its test root must run exactly the modules it names."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SELECTED = ("tests/test_ci_selection_plugin.py", "tests/api/test_admission_pool_budget.py")


def _collect(args: list[str], *, selection: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if key != "AGENT_BOM_PYTEST_SELECTION"}
    if selection is not None:
        env["AGENT_BOM_PYTEST_SELECTION"] = str(selection)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:randomly", "-p", "no:cacheprovider", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _node_ids(result: subprocess.CompletedProcess[str]) -> list[str]:
    assert result.returncode == 0, result.stdout + result.stderr
    return sorted(line for line in result.stdout.splitlines() if "::" in line)


def test_selected_root_collects_the_same_items_as_the_file_arguments(tmp_path: Path) -> None:
    selection = tmp_path / "selection.txt"
    selection.write_text("\n".join(SELECTED) + "\n", encoding="utf-8")

    by_files = _node_ids(_collect(list(SELECTED)))
    by_root = _node_ids(_collect(["tests"], selection=selection))

    assert by_files, "the selected modules must contain tests"
    assert {item.split("::", 1)[0] for item in by_files} == set(SELECTED)
    assert by_root == by_files


def test_a_selected_module_that_does_not_exist_fails_the_run(tmp_path: Path) -> None:
    selection = tmp_path / "selection.txt"
    selection.write_text("tests/test_ci_selection_plugin.py\ntests/test_no_such_module.py\n", encoding="utf-8")

    result = _collect(["tests"], selection=selection)

    assert result.returncode != 0
    assert "tests/test_no_such_module.py" in result.stdout + result.stderr


def test_an_empty_selection_fails_the_run(tmp_path: Path) -> None:
    selection = tmp_path / "selection.txt"
    selection.write_text("\n", encoding="utf-8")

    result = _collect(["tests"], selection=selection)

    assert result.returncode != 0
    assert "selects no test modules" in result.stdout + result.stderr


@pytest.mark.parametrize("workers", ["0", "2"])
def test_workers_keep_the_selection_and_tests_do_not_see_it(tmp_path: Path, workers: str) -> None:
    selection = tmp_path / "selection.txt"
    selection.write_text("tests/test_ci_selection_env.py\n", encoding="utf-8")
    env = {**os.environ, "AGENT_BOM_PYTEST_SELECTION": str(selection)}

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-p", "no:cacheprovider", "-p", "no:randomly", "-rA", "-n", workers],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    # Workers collect only the selected module: one item, not the whole tree.
    assert re.search(r"(collected 1 item|2 workers \[1 item\])", result.stdout), result.stdout
    assert "PASSED tests/test_ci_selection_env.py::test_tests_never_inherit_the_selection" in result.stdout, result.stdout
