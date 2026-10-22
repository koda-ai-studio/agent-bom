#!/usr/bin/env python3
"""Require a successful coverage artifact from every shard before the 75% gate."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from coverage.exceptions import CoverageException

ARTIFACT_NAME = re.compile(r"python311-coverage-shard-(\d+)-attempt-(\d+)")


def coverage_inputs(root: Path, *, shards: int, attempt: int) -> list[Path]:
    """Choose the latest successful artifact per shard, including partial reruns.

    The workflow downloads artifacts from this run only. Successful siblings
    retain their prior-attempt artifacts when GitHub retries failed jobs.
    Attempt-qualified names preserve earlier evidence without overwriting it.
    """
    if shards < 1 or attempt < 1:
        raise ValueError("Shard count and attempt must be positive")
    selected: dict[int, tuple[int, Path]] = {}
    for directory in root.glob("python311-coverage-*"):
        match = ARTIFACT_NAME.fullmatch(directory.name)
        if match is None or not directory.is_dir():
            raise ValueError("Unexpected coverage artifact name")
        shard, generation = map(int, match.groups())
        if shard >= shards or not 1 <= generation <= attempt:
            raise ValueError("Unexpected coverage shard or attempt")
        data = directory / ".coverage"
        if not data.is_file() or data.stat().st_size == 0:
            raise ValueError("Missing or empty coverage data")
        if shard not in selected or generation > selected[shard][0]:
            selected[shard] = generation, data
    if set(selected) != set(range(shards)):
        raise ValueError("Coverage artifacts do not cover every required shard")
    return [selected[shard][1] for shard in range(shards)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    args = parser.parse_args()
    try:
        inputs = coverage_inputs(args.artifact_dir, shards=args.shards, attempt=args.attempt)
        # Pre-read every input: coverage combine can warn and skip corrupt
        # databases, which must not silently turn missing evidence into success.
        from coverage import CoverageData

        for path in inputs:
            data = CoverageData(basename=str(path))
            data.read()
            if not data.measured_files():
                raise ValueError("Coverage artifact contains no measured files")
        subprocess.run([sys.executable, "-m", "coverage", "combine", "--keep", *map(str, inputs)], check=True)
        return subprocess.run([sys.executable, "-m", "coverage", "report", "--show-missing", "--fail-under=75"]).returncode
    except (OSError, ValueError, CoverageException, subprocess.CalledProcessError):
        print("::error::Complete readable coverage from every shard is required", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
