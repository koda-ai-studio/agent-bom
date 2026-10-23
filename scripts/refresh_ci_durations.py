#!/usr/bin/env python3
"""Refresh tests/.ci-durations.json, the per-module seconds the shard planner balances.

Sources, from one run of the suite (each module must appear in only one source):

* ``--log``: a CI job log of ``pytest -v -n N`` with GitHub's per-line
  timestamps. Each worker's gap between consecutive results is charged to the
  module of the test that ended it, so setup and teardown cost is included.
  Download with ``gh api --allow-escape-sequences repos/OWNER/REPO/actions/jobs/JOB_ID/logs``.
* ``--junit``: a ``pytest --junitxml`` report; case times are summed per module.

Local refresh without CI logs::

    uv run pytest tests -m "not network and not slow and not graph_performance" \\
        -n 2 --dist worksteal --junitxml=/tmp/junit.xml
    uv run python scripts/refresh_ci_durations.py --junit /tmp/junit.xml
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET  # nosec B405 - parses our own pytest report
from collections import defaultdict
from datetime import datetime
from pathlib import Path

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "tests" / ".ci-durations.json"
_TIMESTAMP = r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z"
_SESSION_START = re.compile(_TIMESTAMP + r" \d+ workers \[\d+ items?\]")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_RESULT = re.compile(
    _TIMESTAMP + r" \[(?P<worker>gw\d+)\] \[\s*\d+%\] (?:PASSED|FAILED|SKIPPED|XFAIL|XPASS|ERROR) (?P<module>[^\s:]+\.py)::"
)


def _parse_time(value: str) -> datetime:
    whole, _, fraction = value.partition(".")
    return datetime.fromisoformat(f"{whole}.{(fraction or '0')[:6]}")


def seconds_from_log(path: Path) -> dict[str, float]:
    """Charge each xdist worker's gap between results to the module that ended it."""
    seconds: dict[str, float] = defaultdict(float)
    start: datetime | None = None
    last: dict[str, datetime] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = _ANSI.sub("", raw)
        if start is None:
            match = _SESSION_START.search(line)
            if match:
                start = _parse_time(match["ts"])
            continue
        result = _RESULT.search(line)
        if result:
            ended = _parse_time(result["ts"])
            seconds[result["module"]] += max((ended - last.get(result["worker"], start)).total_seconds(), 0.0)
            last[result["worker"]] = ended
    if start is None:
        raise SystemExit(f"{path}: no 'N workers [M items]' line; expected a pytest -v -n N log")
    return dict(seconds)


def _junit_module(case: ET.Element) -> str:
    file = case.get("file")
    if file:
        return Path(file).as_posix()
    return case.get("classname", "").replace(".", "/") + ".py"


def seconds_from_junit(path: Path) -> dict[str, float]:
    """Sum testcase times per module from a pytest junit report."""
    seconds: dict[str, float] = defaultdict(float)
    for case in ET.parse(path).getroot().iter("testcase"):  # nosec B314 - local pytest output
        seconds[_junit_module(case)] += float(case.get("time") or 0.0)
    return dict(seconds)


def _merge(parts: list[dict[str, float]]) -> dict[str, float]:
    merged: dict[str, float] = defaultdict(float)
    for part in parts:
        for module, value in part.items():
            merged[module] += value
    return {module: round(merged[module], 2) for module in sorted(merged)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", nargs="*", type=Path, default=[], help="pytest -v -n N CI job logs")
    parser.add_argument("--junit", nargs="*", type=Path, default=[], help="pytest junitxml reports")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if not args.log and not args.junit:
        parser.error("pass at least one --log or --junit source")
    parts = [seconds_from_log(path) for path in args.log] + [seconds_from_junit(path) for path in args.junit]
    payload = {"unit": "worker-seconds per module", "files": _merge(parts)}
    args.output.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(payload['files'])} module timings to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
