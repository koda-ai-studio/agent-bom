#!/usr/bin/env python3
"""Print key=value posture metrics for the GitHub Action from a result file."""

import json
import os

path = os.environ.get("RESULT_FILE", "")
vuln_count = int(os.environ.get("VULN_COUNT") or "0")
exposure_paths = 0
critical = 0
high = 0


def _walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


try:
    data = json.load(open(path, encoding="utf-8"))
    if isinstance(data, dict) and "runs" in data:
        run = data.get("runs", [{}])[0]
        rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule = rules.get(result.get("ruleId"), {})
            score = float(rule.get("properties", {}).get("security-severity", "0") or "0")
            if score > 9.0:
                critical += 1
            elif score >= 7.0:
                high += 1
    else:
        for item in _walk(data):
            for key in ("exposure_paths", "lateral_paths", "attack_paths"):
                paths = item.get(key)
                if isinstance(paths, list):
                    exposure_paths += len(paths)
            severity = str(item.get("severity") or item.get("level") or "").lower()
            if severity == "critical":
                critical += 1
            elif severity == "high":
                high += 1
    if critical > 0:
        grade = "F"
    elif high > 0:
        grade = "D"
    elif vuln_count > 0:
        grade = "C"
    else:
        grade = "A"
except Exception:
    grade = "unknown"

print(f"exposure_paths_count={exposure_paths}")
print(f"blast_radius_critical_count={critical}")
print(f"posture_grade={grade}")
