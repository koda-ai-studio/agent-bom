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
# Distro packages whose fix may be backported: listed for review, never counted as confirmed findings.
POSSIBLY_AFFECTED = "possibly_affected"
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
                "possibly_affected": props.get("verdict") == POSSIBLY_AFFECTED,
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
                "possibly_affected": finding.get("verdict") == POSSIBLY_AFFECTED,
            }
        )
    for item in data.get("possibly_affected") or []:
        if isinstance(item, dict):
            pkg = item.get("package") if isinstance(item.get("package"), dict) else {}
            rows.append(
                {
                    "severity": "unknown",
                    "location": f"{pkg.get('name') or ''} {pkg.get('version') or ''}".strip(),
                    "rule": str(item.get("id") or ""),
                    "message": str(item.get("detail") or ""),
                    "fix": f"Upstream fix {item['upstream_fixed_version']}" if item.get("upstream_fixed_version") else "",
                    "blast": 0.0,
                    "possibly_affected": True,
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


def _split(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    confirmed = [row for row in rows if not row.get("possibly_affected")]
    return confirmed, [row for row in rows if row.get("possibly_affected")]


def possibly_affected_section(rows: list[dict[str, Any]], limit: int) -> list[str]:
    if not rows:
        return []
    lines = [
        f"**Possibly affected:** {len(rows)} distro package(s) whose fix may be backported; "
        "verify each against the distribution's advisory. These are not counted as findings and do not fail a gate.",
        "",
    ]
    lines += [f"- `{_cell(row['rule'], 80)}`: {_cell(row['message'])}" for row in rows[:limit]]
    if len(rows) > limit:
        lines.append(f"- {len(rows) - limit} more in the result file.")
    return [*lines, ""]


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def scan_outcome(data: dict[str, Any]) -> str:
    """The scanner's own outcome (complete, partial or failed), or empty when it wrote none."""
    if "runs" in data:
        run = (data.get("runs") or [{}])[0] or {}
        return str((run.get("properties") or {}).get("scan_outcome") or "")
    scan_run = data.get("scan_run")
    return str(scan_run.get("outcome") or "") if isinstance(scan_run, dict) else ""


def _has_malicious(data: dict[str, Any]) -> bool:
    if "runs" in data:
        results = ((data.get("runs") or [{}])[0] or {}).get("results") or []
        return any(isinstance(item, dict) and (item.get("properties") or {}).get("is_malicious") for item in results)
    return any(isinstance(item, dict) and item.get("is_malicious") for item in data.get("findings") or [])


def report_only_verdict(path: Path) -> str:
    """How a report-only step reads a scan that exited 1: complete, partial or blocked.

    A known-malicious package and anything the report cannot explain stay blocked,
    because exit 1 then is not a severity verdict the operator chose to ignore.
    """
    data = _load(path)
    outcome = scan_outcome(data)
    return outcome if outcome in {"complete", "partial"} and not _has_malicious(data) else "blocked"


def coverage_lines(outcome: str) -> list[str]:
    if outcome != "partial":
        return []
    return ["**Partial scan:** a collector did not finish, so these results are incomplete. See `scan_run.issues` in the report.  "]


def data_coverage_lines(data: dict[str, Any]) -> list[str]:
    """What the local vulnerability data did not hold, as the report states it."""
    if "runs" in data:
        props = ((data.get("runs") or [{}])[0] or {}).get("properties") or {}
        partial, scope = props.get("vuln_data_partial_sources"), props.get("vuln_data_osv_scope")
    else:
        freshness = data.get("vuln_data_freshness") or {}
        partial, scope = freshness.get("partial_sources"), freshness.get("osv_scope")
    lines = []
    for item in partial or []:
        if isinstance(item, dict):
            source, reason = _cell(str(item.get("source"))), _cell(str(item.get("reason")))
            lines.append(f"**Vulnerability data:** {source} sync is partial ({reason}); it resumes at the next refresh.  ")
    if scope:
        lines.append(
            f"**Vulnerability data:** Local OSV data covers {_cell(', '.join(map(str, scope)), 300)}; other ecosystems were checked live.  "
        )
    return lines


def render_summary(
    rows: list[dict[str, Any]],
    *,
    exit_code: str,
    scan_type: str,
    result_file: str,
    limit: int = 10,
    outcome: str = "",
    data_notes: list[str] | None = None,
) -> str:
    rows, possibly = _split(rows)
    return "\n".join(
        [
            "## agent-bom scan summary",
            "",
            f"**Status:** {status_line(exit_code, len(rows))}  ",
            *coverage_lines(outcome),
            *(data_notes or []),
            f"**Scan type:** `{_cell(scan_type)}` · **Findings:** {len(rows)} ({severity_counts(rows)})  ",
            f"**Result file:** `{_cell(result_file)}`" if result_file else "",
            "",
            "### Top findings (by severity, then blast radius)",
            "",
            findings_table(rows, limit),
            "",
            *possibly_affected_section(possibly, limit),
        ]
    )


def render_comment(
    rows: list[dict[str, Any]], *, exit_code: str, limit: int = 10, outcome: str = "", data_notes: list[str] | None = None
) -> str:
    rows, possibly = _split(rows)
    return "\n".join(
        [
            COMMENT_MARKER,
            "## agent-bom security scan",
            "",
            f"**Status:** {status_line(exit_code, len(rows))}  ",
            *coverage_lines(outcome),
            *(data_notes or []),
            f"**Findings:** {len(rows)} ({severity_counts(rows)})",
            "",
            findings_table(rows, limit),
            "",
            *possibly_affected_section(possibly, limit),
            f"<sub>Generated by [agent-bom]({REPO_URL})</sub>",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    # GitHub reads workflow commands and summaries as UTF-8; a Windows console defaults to cp1252.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["summary", "comment", "report-only-verdict"])
    parser.add_argument("result_file", type=Path)
    parser.add_argument("--exit-code", default=os.environ.get("EXIT_CODE", ""))
    parser.add_argument("--scan-type", default=os.environ.get("INPUT_SCAN_TYPE", "scan"))
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args(argv)
    if args.mode == "report-only-verdict":
        print(report_only_verdict(args.result_file))
        return 0
    rows = load_rows(args.result_file) if args.result_file.is_file() else []
    data = _load(args.result_file)
    outcome = scan_outcome(data)
    notes = data_coverage_lines(data)
    if args.mode == "summary":
        result = str(args.result_file) if args.result_file.is_file() else ""
        rendered = render_summary(
            rows,
            exit_code=args.exit_code,
            scan_type=args.scan_type,
            result_file=result,
            limit=args.limit,
            outcome=outcome,
            data_notes=notes,
        )
    else:
        rendered = render_comment(rows, exit_code=args.exit_code, limit=args.limit, outcome=outcome, data_notes=notes)
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
