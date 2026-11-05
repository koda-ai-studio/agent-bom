#!/usr/bin/env python3
"""Check a SARIF file against what GitHub code scanning accepts for locations.

GitHub rejects the whole upload when a result or related location has no
physical location, or when a URI uses a scheme the checkout does not. Standard
library only: CI runs it on the file the Action wrote.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _uri_problem(location: Any) -> str | None:
    physical = location.get("physicalLocation") if isinstance(location, dict) else None
    artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or not uri:
        return "no physicalLocation.artifactLocation.uri"
    if "://" in uri or uri.startswith(("/", "pkg:", "package:")) or (len(uri) > 1 and uri[1] == ":"):
        return f"URI is not repository-relative: {uri}"
    if "\\" in uri or ".." in uri.split("/"):
        return f"URI is not a clean relative path: {uri}"
    return None


def location_violations(document: dict[str, Any]) -> list[str]:
    """Every way the document's locations would fail or degrade a GitHub upload."""
    violations: list[str] = []
    for run in document.get("runs") or []:
        for result in run.get("results") or []:
            rule = result.get("ruleId", "<no ruleId>")
            locations = result.get("locations") or []
            if not locations:
                violations.append(f"{rule}: no locations")
            for location in locations:
                if problem := _uri_problem(location):
                    violations.append(f"{rule}: location: {problem}")
            for related in result.get("relatedLocations") or []:
                if problem := _uri_problem(related):
                    violations.append(f"{rule}: relatedLocation: {problem}")
            # github/codeql-action computes this hash itself and warns on any other value.
            if "primaryLocationLineHash" in (result.get("partialFingerprints") or {}):
                violations.append(f"{rule}: carries primaryLocationLineHash")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--require-results", action="store_true", help="Fail when the file has no results.")
    parser.add_argument("--require-empty", action="store_true", help="Fail when the file has any result.")
    parser.add_argument("--only-package", help="Fail unless every result names this package and at least one exists.")
    args = parser.parse_args(argv)
    document = json.loads(args.sarif.read_text(encoding="utf-8"))
    results = [result for run in document.get("runs") or [] for result in run.get("results") or []]
    problems = location_violations(document)
    if args.require_results and not results:
        problems.append("expected at least one result, found none")
    if args.require_empty and results:
        problems.append(f"expected no results, found: {sorted({str(result.get('ruleId')) for result in results})}")
    if args.only_package:
        if not results:
            problems.append(f"expected results for {args.only_package}, found none")
        marker = f" in {args.only_package}@"
        for result in results:
            text = str((result.get("message") or {}).get("text") or "")
            if marker not in text:
                problems.append(f"{result.get('ruleId')}: not about {args.only_package}: {text[:200]}")
    for problem in problems:
        print(f"::error::{args.sarif}: {problem}")
    print(f"{args.sarif}: {len(results)} result(s), {len(problems)} problem(s)", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
