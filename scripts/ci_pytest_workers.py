#!/usr/bin/env python3
"""Print the pytest-xdist worker count for a CI test selection.

Hosted ubuntu-latest runners for public repositories have 4 vCPUs and 16 GB
(https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Ordinary selections use every core. A full demo-estate rebuild peaks at about
3.1 GB RSS per worker, and a worker that runs only demo-estate bootstrap tests
grows to about 4.1 GB, so four such workers would exhaust a 16 GB runner.
Selections containing that module are capped at three workers (about 12.3 GB).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from pathlib import PurePosixPath

MEMORY_HEAVY_MODULES = frozenset({"tests/test_demo_estate_bootstrap.py"})
MEMORY_HEAVY_WORKER_CAP = 3


def _available_cpus() -> int | None:
    if hasattr(os, "sched_getaffinity"):
        return len(os.sched_getaffinity(0))
    return os.cpu_count()


def worker_count(files: Iterable[str], *, cpus: int | None) -> int:
    """Return the worker count for *files* on a runner with *cpus* cores."""
    workers = max(1, cpus or 1)
    selected = {PurePosixPath(path).as_posix().removeprefix("./") for path in files}
    if selected & MEMORY_HEAVY_MODULES:
        workers = min(workers, MEMORY_HEAVY_WORKER_CAP)
    return workers


def main(argv: list[str]) -> int:
    print(worker_count(argv, cpus=_available_cpus()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
