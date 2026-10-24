#!/usr/bin/env python3
"""Render the GitHub Action job summary and pull request comment.

Reads an agent-bom SARIF file or JSON report, ranks findings by severity and
then blast radius, and prints Markdown. Standard library only: it runs from
the action checkout against whatever agent-bom release was installed.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_URL = "https://github.com/koda-ai-studio/agent-bom"
COMMENT_MARKER = "<!-- agent-bom-scan-comment -->"
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": 0}


def score_to_severity(score: float) -> str:
    # GitHub code scanning ranges: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
    if score > 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "none"


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _blast(props: dict[str, Any]) -> float:
    reach = sum(len(props.get(key) or []) for key in ("affected_agents", "affected_servers", "exposed_credentials", "exposed_tools"))
    return _float(props.get("risk_score")) * 100 + reach


def _fix(props: dict[str, Any], rule: dict[str, Any]) -> str:
    if props.get("remediation_guidance"):
        return str(props["remediation_guidance"])
    if props.get("fixed_version"):
        return f"Upgrade to {props['fixed_version']}"
    return ""


def _sarif_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    run = (data.get("runs") or [{}])[0] or {}
    rules = {str(rule.get("id")): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", []) if isinstance(rule, dict)}
    rows = []
    for result in run.get("results", []):
        if not isinstance(result, dict):
            continue
        rule_id = str(result.get("ruleId") or "")
        rule = rules.get(rule_id, {})
        props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
        severity = score_to_severity(_float(rule.get("properties", {}).get("security-severity")))
        location = (result.get("locations") or [{}])[0] or {}
        physical = location.get("physicalLocation", {}) if isinstance(location, dict) else {}
        uri = str(physical.get("artifactLocation", {}).get("uri") or "")
        line = physical.get("region", {}).get("startLine")
        rows.append(
            {
                "severity": severity,
                "location": f"{uri}:{line}" if uri and line else uri,
                "rule": rule_id,
                "message": str(result.get("message", {}).get("text") or ""),
                "fix": _fix(props, rule),
                "blast": _blast(props),
            }
        )
    return rows


def _report_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for finding in data.get("findings") or []:
        if not isinstance(finding, dict) or finding.get("suppressed"):
            continue
        asset = finding.get("asset") if isinstance(finding.get("asset"), dict) else {}
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        location = str(asset.get("location") or asset.get("name") or "")
        line = evidence.get("line") or evidence.get("line_number")
        rows.append(
            {
                "severity": str(finding.get("effective_severity") or finding.get("severity") or "unknown").lower(),
                "location": f"{location}:{line}" if location and line else location,
                "rule": str(evidence.get("rule_id") or finding.get("vulnerability_id") or finding.get("finding_type") or ""),
                "message": str(finding.get("title") or ""),
                "fix": str(
                    finding.get("remediation_guidance")
                    or (f"Upgrade to {finding['fixed_version']}" if finding.get("fixed_version") else "")
                ),
                "blast": _blast({**finding, "risk_score": finding.get("risk_score")}),
            }
        )
    return rows


def load_rows(path: Path) -> list[dict[str, Any]]:
    """Return findings ranked by severity, then blast radius (highest first)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    rows = _sarif_rows(data) if "runs" in data else _report_rows(data)
    return sorted(rows, key=lambda row: (-SEVERITY_RANK.get(row["severity"], 0), -row["blast"], row["location"], row["rule"]))


def _cell(value: str, limit: int = 160) -> str:
    text = html.escape(value or "", quote=False).replace("|", "\\|").replace("`", "'")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def findings_table(rows: list[dict[str, Any]], limit: int) -> str:
    if not rows:
        return "No findings."
    lines = ["| Severity | Location | Rule | Finding | Fix |", "|---|---|---|---|---|"]
    for row in rows[:limit]:
        cells = [
            row["severity"].upper(),
            _cell(row["location"]) or "-",
            _cell(row["rule"], 80),
            _cell(row["message"]),
            _cell(row["fix"]) or "-",
        ]
        lines.append("| " + " | ".join(cells) + " |")
    if len(rows) > limit:
        lines.append("")
        lines.append(f"{len(rows) - limit} more finding(s) in the result file.")
    return "\n".join(lines)


def severity_counts(rows: list[dict[str, Any]]) -> str:
    counts = {name: 0 for name in ("critical", "high", "medium", "low")}
    for row in rows:
        if row["severity"] in counts:
            counts[row["severity"]] += 1
    return ", ".join(f"{count} {name}" for name, count in counts.items())


def status_line(exit_code: str, total: int) -> str:
    if exit_code == "0":
        return "Passed: no finding met the configured gates" if total else "Clean: no findings"
    if exit_code == "1":
        return f"Failed: {total} finding(s); at least one met a configured gate" if total else "Failed: scan error"
    if exit_code == "2":
        return "Failed: invalid or empty scan input"
    if exit_code == "3":
        return "Failed: vulnerability database freshness gate"
    return f"Failed: scan error (exit code {exit_code})"


def render_summary(rows: list[dict[str, Any]], *, exit_code: str, scan_type: str, result_file: str, limit: int = 10) -> str:
    return "\n".join(
        [
            "## agent-bom scan summary",
            "",
            f"**Status:** {status_line(exit_code, len(rows))}  ",
            f"**Scan type:** `{_cell(scan_type)}` · **Findings:** {len(rows)} ({severity_counts(rows)})  ",
            f"**Result file:** `{_cell(result_file)}`" if result_file else "",
            "",
            "### Top findings (by severity, then blast radius)",
            "",
            findings_table(rows, limit),
            "",
        ]
    )


def render_comment(rows: list[dict[str, Any]], *, exit_code: str, limit: int = 10) -> str:
    return "\n".join(
        [
            COMMENT_MARKER,
            "## agent-bom security scan",
            "",
            f"**Status:** {status_line(exit_code, len(rows))}  ",
            f"**Findings:** {len(rows)} ({severity_counts(rows)})",
            "",
            findings_table(rows, limit),
            "",
            f"<sub>Generated by [agent-bom]({REPO_URL})</sub>",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["summary", "comment"])
    parser.add_argument("result_file", type=Path)
    parser.add_argument("--exit-code", default=os.environ.get("EXIT_CODE", ""))
    parser.add_argument("--scan-type", default=os.environ.get("INPUT_SCAN_TYPE", "scan"))
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args(argv)
    rows = load_rows(args.result_file) if args.result_file.is_file() else []
    if args.mode == "summary":
        result = str(args.result_file) if args.result_file.is_file() else ""
        sys.stdout.write(render_summary(rows, exit_code=args.exit_code, scan_type=args.scan_type, result_file=result, limit=args.limit))
    else:
        sys.stdout.write(render_comment(rows, exit_code=args.exit_code, limit=args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
