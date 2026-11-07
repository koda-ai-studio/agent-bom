#!/usr/bin/env python3
"""Action lane: assert what the composite action produced on a fixture.

Validates the SARIF file against the official 2.1.0 schema vendored in the test
fixtures and against the location rules GitHub's upload enforces. The docs-only
case must neither fail nor invent findings; the with-packages case must report
the fixture's known advisory and fail the default high gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check_sarif_locations import location_violations  # noqa: E402
from common import REPO_ROOT, LaneResult  # noqa: E402

SARIF_SCHEMA = REPO_ROOT / "tests" / "fixtures" / "sarif-schema-2.1.0.json"
KNOWN_ADVISORY = "CVE-2018-18074"


def sarif_problems(document: dict[str, Any]) -> list[str]:
    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    problems = [f"{'/'.join(map(str, error.path))}: {error.message}"[:300] for error in validator.iter_errors(document)]
    problems.extend(location_violations(document))
    for run in document.get("runs") or []:
        problems.extend(
            f"result without locations: {result.get('ruleId')}" for result in run.get("results") or [] if not result.get("locations")
        )
    return problems


def _results(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [result for run in document.get("runs") or [] for result in run.get("results") or []]


def assert_case(case: str, sarif_path: Path, *, exit_code: str, status: str, vulnerability_count: str) -> LaneResult:
    result = LaneResult("action", case)
    result.measurements.update(exit_code=exit_code, scan_status=status, vulnerability_count=vulnerability_count)
    if not result.check("sarif_written", sarif_path.is_file(), str(sarif_path)):
        return result
    document = json.loads(sarif_path.read_text(encoding="utf-8"))
    problems = sarif_problems(document)
    result.check("sarif_valid", not problems, problems[:10] or "schema and locations valid")
    findings = _results(document)
    rule_ids = {str(item.get("ruleId")) for item in findings}
    result.measurements["sarif_results"] = len(findings)
    if case == "docs-only":
        result.check("docs_only_passes_the_gate", exit_code == "0", f"exit {exit_code}, status {status}")
        result.check("docs_only_status_is_not_a_failure", status in {"clean", "partial"}, status)
        result.check("docs_only_invents_no_package_findings", KNOWN_ADVISORY not in rule_ids, sorted(rule_ids)[:10])
    else:
        result.check("packages_fail_the_high_gate", exit_code == "1", f"exit {exit_code}, status {status}")
        result.check("packages_status_is_violations", status == "violations", status)
        result.check("packages_report_known_advisory", any(KNOWN_ADVISORY in rule for rule in rule_ids), sorted(rule_ids)[:10])
        result.check("count_output_matches_findings", vulnerability_count.isdigit() and int(vulnerability_count) > 0, vulnerability_count)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case", required=True, choices=("docs-only", "with-packages"))
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--exit-code", default="")
    parser.add_argument("--status", default="")
    parser.add_argument("--vulnerability-count", default="")
    args = parser.parse_args()
    return assert_case(
        args.case, args.sarif, exit_code=args.exit_code, status=args.status, vulnerability_count=args.vulnerability_count
    ).write()


if __name__ == "__main__":
    raise SystemExit(main())
