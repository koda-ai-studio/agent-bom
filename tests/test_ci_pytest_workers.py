"""Worker counts for CI pytest lanes stay within hosted-runner CPU and memory."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts import ci_pytest_workers

ROOT = Path(__file__).resolve().parents[1]

DEMO = "tests/test_demo_estate_bootstrap.py"


@pytest.mark.parametrize(
    ("files", "cpus", "expected"),
    [
        (["tests/test_policy_engine.py"], 4, 4),
        ([DEMO], 4, 3),
        (["tests/test_policy_engine.py", DEMO], 4, 3),
        (["tests/test_policy_engine.py"], 2, 2),
        ([DEMO], 2, 2),
        (["tests/test_policy_engine.py"], 1, 1),
        (["tests/test_policy_engine.py"], None, 1),
        ([], 4, 4),
        (["./tests/test_demo_estate_bootstrap.py"], 4, 3),
    ],
)
def test_worker_count_caps_memory_heavy_selections(files: list[str], cpus: int | None, expected: int) -> None:
    assert ci_pytest_workers.worker_count(files, cpus=cpus) == expected


def test_cli_prints_a_single_integer_for_the_selection() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/ci_pytest_workers.py", "tests/test_policy_engine.py", DEMO],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip().isdigit()
    assert 1 <= int(result.stdout) <= 3
