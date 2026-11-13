#!/usr/bin/env python3
"""Wait until PyPI serves a release, so the post-release pin job can relock against it.

``pypa/gh-action-pypi-publish`` returns once the upload is accepted, but the
project's JSON API and its simple index (which ``uv lock`` resolves from) can
lag behind. The pin job's ``bump-version.py --published`` relocks the plugin
launchers, and a relock that runs before the index lists the version fails with
"no version of agent-bom==X".

Both endpoints must list the version. Polls with exponential backoff up to
``--timeout`` seconds and exits 1 with a workflow error annotation if PyPI never
serves it.

Usage::

    python scripts/wait_for_pypi_release.py 0.115.0 --timeout 600
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable

PROJECT = "agent-bom"
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
FIRST_INTERVAL = 10.0
MAX_INTERVAL = 60.0
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

Fetch = Callable[..., Any]


def _fetch_json(url: str, accept: str | None = None) -> Any:
    headers = {"User-Agent": "agent-bom-release-pin-sync", "Cache-Control": "no-cache"}
    if accept:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - fixed https PyPI URLs
        return json.loads(response.read().decode("utf-8"))


def _served(project: str, version: str, fetch: Fetch) -> tuple[bool, bool]:
    try:
        release = fetch(f"https://pypi.org/pypi/{project}/{version}/json")
        in_json = str(release.get("info", {}).get("version")) == version
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        in_json = False
    try:
        index = fetch(f"https://pypi.org/simple/{project}/", accept=SIMPLE_JSON)
        in_index = version in (index.get("versions") or [])
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        in_index = False
    return in_json, in_index


def wait_for_release(
    project: str,
    version: str,
    *,
    timeout: float,
    fetch: Fetch = _fetch_json,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """True once PyPI's JSON API and simple index both list *version*; False at the deadline."""
    deadline = clock() + timeout
    interval = FIRST_INTERVAL
    attempt = 0
    while True:
        attempt += 1
        in_json, in_index = _served(project, version, fetch)
        if in_json and in_index:
            print(f"PyPI serves {project}=={version} (attempt {attempt})")
            return True
        remaining = deadline - clock()
        if remaining <= 0:
            return False
        print(f"PyPI does not serve {project}=={version} yet (JSON API: {in_json}, simple index: {in_index}); retrying in {interval:.0f}s")
        sleep(min(interval, max(remaining, 1.0)))
        interval = min(interval * 2, MAX_INTERVAL)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version")
    parser.add_argument("--project", default=PROJECT)
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds to wait (default 600)")
    args = parser.parse_args(argv)
    if not _SEMVER.match(args.version):
        print(f"ERROR: expected a bare semver like 0.115.0, got {args.version!r}", file=sys.stderr)
        return 2
    if wait_for_release(args.project, args.version, timeout=args.timeout):
        return 0
    print(
        f"::error title=PyPI does not serve {args.project}=={args.version}::"
        f"After {args.timeout:.0f}s PyPI's JSON API or simple index still does not list {args.version}, "
        "so the launcher lock files cannot be regenerated. Re-run this job once PyPI serves the release."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
