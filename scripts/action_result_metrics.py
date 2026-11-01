#!/usr/bin/env python3
"""Print key=value posture metrics for the GitHub Action from a result file.

The grade and counts are read from what the scanner wrote (``posture_grade``,
``exposure_paths.path_count`` and the ``blast_radius`` rows of a JSON report;
``runs[0].properties`` and ``security-severity`` of a SARIF file). Nothing is
re-derived from nested severities: when the artifact carries no grade the
output says ``unknown`` rather than inventing a letter that disagrees with the
report.
"""

from __future__ import annotations

import json
import os
from typing import Any

CRITICAL_SECURITY_SEVERITY = 9.0


def _int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _grade(value: Any) -> str:
    text = str(value or "").strip()
    return text if text else "unknown"


def _sarif_metrics(document: dict[str, Any]) -> tuple[int, int, str]:
    runs = document.get("runs") or [{}]
    run = runs[0] if isinstance(runs[0], dict) else {}
    rules = {rule.get("id"): rule for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules", []) if isinstance(rule, dict)}
    critical = 0
    for result in run.get("results") or []:
        if not isinstance(result, dict):
            continue
        properties = result.get("properties") or {}
        if properties.get("verdict") == "possibly_affected":
            continue
        raw = properties.get("security-severity")
        if raw is None:
            rule = rules.get(result.get("ruleId")) or {}
            raw = (rule.get("properties") or {}).get("security-severity")
        try:
            score = float(str(raw))
        except (TypeError, ValueError):
            continue
        if score >= CRITICAL_SECURITY_SEVERITY:
            critical += 1
    raw_properties = run.get("properties")
    run_properties: dict[str, Any] = raw_properties if isinstance(raw_properties, dict) else {}
    return _int(run_properties.get("exposure_path_count")), critical, _grade(run_properties.get("posture_grade"))


def _json_metrics(document: dict[str, Any]) -> tuple[int, int, str]:
    exposure = document.get("exposure_paths")
    if isinstance(exposure, dict):
        exposure_paths = _int(exposure.get("path_count"))
    elif isinstance(exposure, list):
        exposure_paths = sum(1 for path in exposure if not (isinstance(path, dict) and path.get("suppressed")))
    else:
        exposure_paths = 0
    rows = document.get("blast_radius")
    if isinstance(rows, list):
        critical = sum(1 for row in rows if _is_critical(row) and not row.get("suppressed"))
    else:
        findings = document.get("findings")
        critical = sum(1 for item in findings if _is_critical(item)) if isinstance(findings, list) else 0
    return exposure_paths, critical, _grade(document.get("posture_grade"))


def _is_critical(row: Any) -> bool:
    return isinstance(row, dict) and str(row.get("severity") or "").lower() == "critical"


def main() -> None:
    exposure_paths, critical, grade = 0, 0, "unknown"
    try:
        with open(os.environ.get("RESULT_FILE", ""), encoding="utf-8") as stream:
            data = json.load(stream)
        if isinstance(data, dict) and "runs" in data:
            exposure_paths, critical, grade = _sarif_metrics(data)
        elif isinstance(data, dict):
            exposure_paths, critical, grade = _json_metrics(data)
    except Exception:  # noqa: BLE001 - a missing or unreadable artifact is reported as unknown, never as a grade
        exposure_paths, critical, grade = 0, 0, "unknown"
    print(f"exposure_paths_count={exposure_paths}")
    print(f"blast_radius_critical_count={critical}")
    print(f"posture_grade={grade}")


# Run on import as well as execution: action.yml and the tests load this file with
# ``python3 <path>`` / ``runpy.run_path``, neither of which sets ``__main__``.
main()
