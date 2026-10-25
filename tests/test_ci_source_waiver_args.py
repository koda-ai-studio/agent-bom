"""The workflow preserves literal arguments with and without a source-test waiver."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize("waived", ["true", "false", ""])
def test_source_test_waiver_is_one_optional_argument(waived):
    root = Path(__file__).resolve().parents[1]
    ci = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    steps = [step for job in ci["jobs"].values() for step in job.get("steps", [])]
    step = next(step for step in steps if "check_tests_accompany_source.py" in step.get("run", ""))
    result = subprocess.run(
        ["bash", "-eu", "-c", "uv() { printf '%s\\n' \"$@\"; }\n" + step["run"]],
        env={**os.environ, "BASE_SHA": "literal base *", "WAIVED": waived},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "run",
        "python",
        "scripts/check_tests_accompany_source.py",
        "--base",
        "literal base *",
        *(["--waived"] if waived == "true" else []),
    ]
