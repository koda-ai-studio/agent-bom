#!/usr/bin/env python3
"""Render bounded, actionable issue details from retained container SARIF."""

from __future__ import annotations

import argparse
import html
import json
import math
from pathlib import Path

MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_ROWS = 50


def _cell(value: object, limit: int = 240) -> str:
    text = " ".join(str(value if value is not None else "unknown").split())[:limit]
    text = html.escape(text).replace("@", "@\u200b")
    for char in ("\\", "|", "`", "[", "]", "*", "_"):
        text = text.replace(char, "\\" + char)
    return text


def _epss(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1:
        return f"{value:.2%}"
    return "unknown"


def _rows(report: dict) -> tuple[list[str], int]:
    rows = []
    seen = set()
    for run in report.get("runs", []):
        rules = {rule["id"]: rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for finding in run.get("results", []):
            props = finding.get("properties", {})
            fixed = props.get("fixed_version")
            if finding.get("level") not in {"error", "warning"} or not isinstance(fixed, str) or not fixed.strip():
                continue
            advisory = finding.get("ruleId", "unknown")
            provenance = props.get("package_version_provenance") or {}
            package, installed = provenance.get("declared_name", "unknown"), provenance.get("resolved_version", "unknown")
            key = (advisory, package, installed, fixed)
            if key in seen:
                continue
            seen.add(key)
            rule = rules.get(advisory, {})
            score = rule.get("properties", {}).get("security-severity", "unknown")
            impact = rule.get("fullDescription", {}).get("text") or rule.get("shortDescription", {}).get("text") or "See retained SARIF"
            kev = {True: "Yes", False: "No"}.get(props.get("is_kev"), "unknown")
            row = (advisory, package, installed, fixed, score, impact, kev, _epss(props.get("epss_score")))
            if len(rows) < MAX_ROWS:
                rows.append("| " + " | ".join(_cell(value) for value in row) + " |")
    return rows, len(seen)


def render(report: dict, *, platform: str, image_id: str, category: str, evidence: str) -> str:
    rows, total = _rows(report)
    outcomes = sorted({str(run.get("properties", {}).get("scan_outcome", "unknown")) for run in report.get("runs", [])})
    lines = [
        "## Automated Base Image Vulnerability Alert",
        "",
        "Daily image rescan found fixable **MEDIUM+** findings in `agentbom/agent-bom:latest`.",
        "",
        f"- Platform: {_cell(platform)}",
        f"- Image ID: {_cell(image_id)}",
        f"- SARIF category: {_cell(category)}",
        "- Source workflow: `.github/workflows/container-rescan.yml`",
        "- Policy: `agent-bom image --fail-on-severity medium --exclude-unfixable`",
        f"- Recorded scan coverage: {_cell(', '.join(outcomes) or 'unknown')}",
        f"- Evidence: {_cell(evidence, 500)}",
        "",
        f"### Fixable findings ({total})",
        "",
        "| Advisory | Package | Installed | Fixed | CVSS | Impact | KEV | EPSS |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
        *rows,
        "",
        "### Why remediate",
        "",
        "The published image contains dependency versions matched to advisories with available fixes. "
        + "Image inventory does not establish runtime reachability or successful exploitation. "
        + "CVSS describes advisory severity; KEV and EPSS are recorded threat context, not proof that this deployment is exploitable.",
        "",
        "### Remediation and verification",
        "",
        "1. Upgrade the affected dependency to a compatible fixed version, or remove it if unused.",
        "2. Rebuild and publish the affected platform image; deploy the new digest.",
        "3. Run a complete rescan of the published digest under the same policy before closing this issue.",
        "",
    ]
    if total > MAX_ROWS:
        lines.append(f"Showing the first {MAX_ROWS} distinct findings; retained SARIF contains the complete list.\n")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    for name in ("platform", "image-id", "category", "evidence"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.report.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        parser.error("container report exceeds the issue renderer size limit")
    body = render(json.loads(raw), platform=args.platform, image_id=args.image_id, category=args.category, evidence=args.evidence)
    args.output.write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()
