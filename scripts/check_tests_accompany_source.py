#!/usr/bin/env python3
"""Fail a pull request that changes Python source without changing any test.

Every behaviour change lands with a test that failed before it (see the
``develop`` skill in ``.agents/skills``). A maintainer can waive the check for
a change that cannot carry a test, such as a pure rename or a release bump, by
applying the ``no-tests-needed`` label; the workflow passes ``--waived``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

SOURCE_PREFIX = "src/agent_bom/"
TEST_PREFIX = "tests/"


def changed_files(base: str) -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in out.stdout.splitlines() if line]


def source_without_tests(files: list[str]) -> list[str]:
    source = [f for f in files if f.startswith(SOURCE_PREFIX) and f.endswith(".py")]
    if any(f.startswith(TEST_PREFIX) for f in files):
        return []
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Base commit or ref of the pull request")
    parser.add_argument("--waived", action="store_true", help="A maintainer applied the no-tests-needed label")
    args = parser.parse_args(argv)

    missing = source_without_tests(changed_files(args.base))
    if not missing:
        print("OK: source changes carry test changes.")
        return 0
    listed = "\n".join(f"  {f}" for f in missing)
    if args.waived:
        print(f"WAIVED (no-tests-needed label): source changed without tests:\n{listed}")
        return 0
    print(
        "FAIL: Python source changed but no file under tests/ did:\n"
        f"{listed}\n"
        "Add a test that fails without the change (red), then passes with it (green).\n"
        "If the change cannot carry a test, ask a maintainer to apply the no-tests-needed label and re-run this job."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
