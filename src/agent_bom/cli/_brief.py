"""Render the control plane's executive brief without recomputing its evidence."""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from typing import Any

import click

from agent_bom.cli._findings_group import _common_api_options, _emit_json, _make_client, _run_request
from agent_bom.core.trend import trend_sentence
from agent_bom.security import sanitize_text


def _text(value: object) -> str:
    text = sanitize_text(str(value if value is not None else "Not recorded"), max_len=1000)
    text = " ".join(text.splitlines())
    return re.sub(r"([\\`*_{}\[\]()#+!|>])", r"\\\1", html.escape(text, quote=False))


_ADVISORY_ID = re.compile(r"^(CVE|GHSA|OSV|PYSEC|RUSTSEC|GO|MAL)-", re.I)


def _finding_label(row: Mapping[str, Any]) -> str:
    """Advisory ids read as-is; other findings use their title instead of an internal id."""
    identifier = str(row.get("vulnerability_id") or "")
    if _ADVISORY_ID.match(identifier):
        return identifier
    return str(row.get("title") or identifier or "Untitled finding")


def brief_trend(payload: Mapping[str, Any]) -> str:
    """Better/worse from the newest comparable scan-history point; never inferred across scopes."""
    points = (payload.get("scan_history") or {}).get("data_points") or []
    comparison = (points[0].get("comparison") or {}) if points else {}
    if comparison.get("status") != "comparable":
        return "Trend: not comparable with the previous scan (" + str(comparison.get("reason") or "no previous scan") + ")."
    return "Trend: " + trend_sentence(int(comparison.get("new_findings") or 0), int(comparison.get("no_longer_detected") or 0))


def render_markdown(payload: Mapping[str, Any]) -> str:
    posture, issues, compliance = payload["posture"], payload["issues"], payload["compliance"]
    lines = [
        "# Executive brief" + (" — Sample data" if payload.get("sample_data") else ""),
        "",
        f"Tenant: {_text(payload['tenant_id'])} · Generated: {_text(payload['generated_at'])}",
        "",
        "## Current posture",
        "",
        f"{_text(posture.get('summary'))}",
        f"Open issue groups: {_text(issues['total'])} · Critical: {_text(issues['critical'])} · "
        f"High: {_text(issues['high'])} · KEV: {_text(issues.get('kev'))}",
        "Counts are correlated issue groups, not finding occurrences.",
        _text(brief_trend(payload)),
        "",
        "## Remediation priorities",
        "",
        "| Finding | Component | Owner | SLA due | SLA basis |",
        "|---|---|---|---|---|",
    ]
    for row in payload["remediation_priorities"]:
        cells = (
            _finding_label(row),
            row.get("component") or row.get("package") or "—",
            row.get("owner") or "Unassigned",
            row.get("sla_due_at") or "—",
            row.get("sla_policy") or row.get("sla_due_at_source") or "—",
        )
        lines.append("| " + " | ".join(_text(value) for value in cells) + " |")
    if not payload["remediation_priorities"]:
        lines.append("No remediation priorities returned by the current overview.")
    lines += ["", "## Ranked exposure paths", ""]
    paths = payload.get("exposure_paths")
    if paths is None:
        lines.append("Path evidence unavailable; this does not establish that no exposure exists.")
    else:
        lines.append(f"Snapshot: {_text(paths.get('scan_id'))} · Generation: {_text(paths.get('snapshot_generation'))}")
        for path in paths["paths"]:
            lines.append(
                f"- {_text(path.get('source', {}).get('label'))} → {_text(path.get('target', {}).get('label'))} · "
                f"Severity: {_text(path.get('severity'))} · Reachability: {_text(path.get('reachability'))}"
            )
        if not paths["paths"]:
            lines.append("No paths returned for this snapshot.")
        coverage, completeness = paths.get("collection_coverage") or {}, paths.get("completeness") or {}
        lines.append(f"Collection coverage: {_text(coverage.get('status'))} · {_text(coverage.get('reason'))}")
        lines.append(
            f"Paths returned: {_text(completeness.get('returned'))} of {_text(completeness.get('total'))} · "
            f"Completeness: {_text(completeness.get('status'))} · {_text(completeness.get('reason'))}"
        )
    lines += ["", "## Technical control evidence", ""]
    lines.append(
        f"Status: {_text(compliance['overall_status'])} · "
        f"Evaluated: {_text(compliance['evaluated_controls'])}/{_text(compliance['total_controls'])} controls"
    )
    lines.append(f"Latest scan: {_text(compliance['latest_scan'])}")
    lines += ["", "| Framework | Passed | Warning | Failed | Not evaluated |", "|---|---|---|---|---|"]
    for name, counts in compliance["frameworks"].items():
        if counts.get("scored"):
            cells = (name, counts.get("pass"), counts.get("warning"), counts.get("fail"), counts.get("not_evaluated"))
            lines.append("| " + " | ".join(_text(value) for value in cells) + " |")
    lines += ["", "## Scope-specific scan history", ""]
    for point in payload["scan_history"]["data_points"]:
        comparison = point["comparison"]
        lines.append(
            f"- Scan {_text(point.get('scan_id'))} · {_text(point.get('timestamp'))} · "
            f"Comparison: {_text(comparison['status'])} · Reason: {_text(comparison.get('reason'))}"
        )
    if not payload["scan_history"]["data_points"]:
        lines.append("No recorded scan history.")
    lines += ["", "## Evidence and next steps", "", _text(payload["evidence_boundary"]), ""]
    lines.append(
        f"Download the signed pack from {_text(payload['links']['evidence_pack'])} on the same control plane; "
        "verify its signature and scope."
    )
    return "\n".join(lines) + "\n"


@click.command(name="brief")
@click.option("--limit", type=click.IntRange(1, 25), default=5, show_default=True)
@click.option("--format", "output_format", type=click.Choice(["markdown", "json"]), default="markdown", show_default=True)
@_common_api_options
def brief_cmd(
    api_url: str | None, api_key: str | None, bearer_token: str | None, tenant_id: str | None, limit: int, output_format: str
) -> None:
    """Export an executive brief from the authenticated control plane."""
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.executive_brief(limit=limit))
    if output_format == "json":
        _emit_json(payload)
    else:
        click.echo(render_markdown(payload), nl=False)
