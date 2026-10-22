"""Exercise actual coverage merging and fail-closed shard evidence handling."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from coverage import CoverageData

from scripts.combine_ci_coverage import coverage_inputs

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/combine_ci_coverage.py"


def artifact(root, shard, attempt, source, lines):
    directory = root / f"python311-coverage-shard-{shard}-attempt-{attempt}"
    directory.mkdir(parents=True)
    path = directory / ".coverage"
    data = CoverageData(basename=str(path))
    data.add_lines({str(source): lines})
    data.write()
    return path


def run_gate(tmp_path, *, shards=2, attempt=2):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / "artifacts"), "--shards", str(shards), "--attempt", str(attempt)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )


def test_combines_all_shards_and_preserves_prior_attempt_evidence(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("first = 1\nsecond = 2\n")
    root = tmp_path / "artifacts"
    old = artifact(root, 0, 1, source, [1])
    latest = artifact(root, 0, 2, source, [2])
    sibling = artifact(root, 1, 1, source, [1])
    assert coverage_inputs(root, shards=2, attempt=2) == [latest, sibling]
    result = run_gate(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(path.exists() for path in (old, latest, sibling))


def test_combined_coverage_still_requires_75_percent(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("first = 1\nsecond = 2\n")
    for shard in range(2):
        artifact(tmp_path / "artifacts", shard, 1, source, [1])
    result = run_gate(tmp_path)
    assert result.returncode != 0
    assert "fail-under=75" in result.stdout


@pytest.mark.parametrize("defect", ["missing", "empty", "corrupt", "no-measurements", "future-attempt", "extra-shard"])
def test_missing_or_invalid_evidence_cannot_pass_with_a_healthy_sibling(tmp_path, defect):
    source = tmp_path / "sample.py"
    source.write_text("first = 1\nsecond = 2\n")
    root = tmp_path / "artifacts"
    artifact(root, 0, 1, source, [1, 2])
    if defect != "missing":
        bad = artifact(root, 2 if defect == "extra-shard" else 1, 3 if defect == "future-attempt" else 1, source, [1])
        if defect in {"empty", "corrupt"}:
            bad.write_bytes(b"" if defect == "empty" else b"invalid database")
        elif defect == "no-measurements":
            bad.unlink()
            data = CoverageData(basename=str(bad))
            data.erase()
            data.write()
    assert run_gate(tmp_path).returncode != 0


def test_obsolete_attempt_cannot_inflate_latest_successful_coverage(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("first = 1\nsecond = 2\n")
    root = tmp_path / "artifacts"
    artifact(root, 0, 1, source, [1, 2])
    artifact(root, 0, 2, source, [1])
    artifact(root, 1, 1, source, [1])
    assert run_gate(tmp_path).returncode != 0
