#!/usr/bin/env python3
"""Classify retained scanner evidence without treating a failed scan as a CVE."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

MAX_REPORT_BYTES = 64 * 1024 * 1024


def classify(path: Path, table: str, sarif: str) -> str:
    """Only complete successful reports can clear an existing issue."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            return "inconclusive"
        report = json.loads(raw)
        runs = report["runs"]
        if report["version"] != "2.1.0" or not isinstance(runs, list) or not runs:
            return "inconclusive"
        complete = table == sarif == "success"
        actionable = False
        for run in runs:
            if run["tool"]["driver"]["name"] != "agent-bom" or not isinstance(run["results"], list):
                return "inconclusive"
            for finding in run["results"]:
                fixed = finding.get("properties", {}).get("fixed_version")
                if finding.get("level") in {"error", "warning"} and isinstance(fixed, str) and fixed.strip():
                    actionable = True
            complete &= run.get("properties", {}).get("scan_outcome") == "complete"
            invocations = run.get("invocations")
            if not isinstance(invocations, list) or not invocations:
                complete = False
                continue
            for invocation in invocations:
                complete &= invocation.get("executionSuccessful") is True
                for notification in invocation.get("toolExecutionNotifications", []):
                    if notification.get("properties", {}).get("affectsCoverage") is not False:
                        complete = False
        return "actionable" if actionable else "clean" if complete else "inconclusive"
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return "inconclusive"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--table", required=True)
    parser.add_argument("--sarif", required=True)
    args = parser.parse_args()
    status = classify(args.report, args.table, args.sarif)
    Path("scan-triage.json").write_text(json.dumps({"status": status, "table": args.table, "sarif": args.sarif}) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"status={status}\n")
    print(f"Container scan evidence: {status}")


if __name__ == "__main__":
    main()
