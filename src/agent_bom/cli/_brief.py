"""Render the control plane's executive brief without recomputing its evidence."""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import click

from agent_bom.cli._findings_group import _common_api_options, _emit_json, _make_client, _run_request
from agent_bom.core.sla import sla_status_text
from agent_bom.core.trend import trend_sentence
from agent_bom.security import sanitize_text

_INLINE_MARKUP = re.compile(r"([\\`*~\[\]|])")
# Emphasis needs an underscore at a word edge; snake_case identifiers stay readable.
_EDGE_UNDERSCORE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")
_LINE_START_MARKER = re.compile(r"^([#>+=-])")
_LINE_START_LIST = re.compile(r"^(\d+)([.)])")


def _text(value: object) -> str:
    """Untrusted text as inert Markdown: no links, images, HTML, code, emphasis or new block."""
    text = sanitize_text(str(value if value is not None else "Not recorded"), max_len=1000)
    text = html.escape(" ".join(text.splitlines()), quote=False)
    text = _EDGE_UNDERSCORE.sub(r"\\_", _INLINE_MARKUP.sub(r"\\\1", text))
    return _LINE_START_LIST.sub(r"\1\\\2", _LINE_START_MARKER.sub(r"\\\1", text, count=1), count=1)


def _when(value: object) -> str:
    """An ISO timestamp to the minute in UTC; anything else as recorded."""
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return _text(value)
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M") + (" UTC" if moment.tzinfo is not None else "")


def _path_lines(paths: list[Mapping[str, Any]]) -> list[str]:
    """One line per exposed target, naming the entry points that reach it."""
    groups: dict[tuple[str, str, str], list[str]] = {}
    for path in paths:
        key = (
            _text(path.get("target", {}).get("label")),
            _text(path.get("severity")),
            _text(path.get("reachability")),
        )
        source = _text(path.get("source", {}).get("label"))
        if source not in groups.setdefault(key, []):
            groups[key].append(source)
    lines = []
    for (target, severity, reachability), sources in groups.items():
        shown = ", ".join(sources[:3]) + (f" +{len(sources) - 3} more" if len(sources) > 3 else "")
        lines.append(f"- {shown} → {target} · Severity: {severity} · Reachability: {reachability}")
    return lines


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
        f"Tenant: {_text(payload['tenant_id'])} · Generated: {_when(payload['generated_at'])}",
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
            f"{_when(row.get('sla_due_at'))} ({_text(row.get('sla_status_text') or sla_status_text(row.get('sla_due_at')))})"
            if row.get("sla_due_at")
            else "No SLA",
            row.get("sla_policy") or row.get("sla_due_at_source") or "—",
        )
        # The SLA cell is built from already-rendered parts.
        rendered = [value if index == 3 and row.get("sla_due_at") else _text(value) for index, value in enumerate(cells)]
        lines.append("| " + " | ".join(rendered) + " |")
    if not payload["remediation_priorities"]:
        lines.append("No remediation priorities returned by the current overview.")
    lines += ["", "## Ranked exposure paths", ""]
    paths = payload.get("exposure_paths")
    if paths is None:
        lines.append("Path evidence unavailable; this does not establish that no exposure exists.")
    else:
        scan_id, generation = str(paths.get("scan_id") or ""), str(paths.get("snapshot_generation") or "")
        snapshot = f"Snapshot: {_text(scan_id or None)}"
        lines.append(snapshot if generation and generation in scan_id else f"{snapshot} · Generation: {_text(generation or None)}")
        lines += _path_lines(paths["paths"])
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
    lines.append(f"Latest scan: {_when(compliance['latest_scan'])}")
    lines += ["", "| Framework | Passed | Warning | Failed | Not evaluated |", "|---|---|---|---|---|"]
    for name, counts in compliance["frameworks"].items():
        if counts.get("scored"):
            cells = (name, counts.get("pass"), counts.get("warning"), counts.get("fail"), counts.get("not_evaluated"))
            lines.append("| " + " | ".join(_text(value) for value in cells) + " |")
    lines += ["", "## Scope-specific scan history", ""]
    for point in payload["scan_history"]["data_points"]:
        comparison = point["comparison"]
        reason = comparison.get("reason")
        lines.append(
            f"- Scan {_text(point.get('scan_id'))} · {_when(point.get('timestamp'))} · Comparison: {_text(comparison['status'])}"
            + (f" · Reason: {_text(reason)}" if reason and comparison["status"] != "comparable" else "")
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
