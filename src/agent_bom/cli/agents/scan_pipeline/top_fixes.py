"""The short "top fixes" block that ends a scan whose report went to a file.

A console scan already prints the full remediation plan. When the report is
written to a file (the documented first run writes HTML), the terminal would
otherwise end at the file path, so the first result has no visible action.
The ranking is the remediation plan's own; nothing is re-scored here.
"""

from __future__ import annotations

from typing import Any

from rich.markup import escape

from agent_bom.models import AIBOMReport
from agent_bom.output.console_remediation import build_remediation_plan
from agent_bom.output.finding_views import cve_findings
from agent_bom.security import sanitize_sensitive_payload

TOP_FIX_LIMIT = 3


def _actionable(report: AIBOMReport) -> list[dict[str, Any]]:
    findings = cve_findings(report)
    if not findings:
        return []
    plan = sanitize_sensitive_payload(build_remediation_plan(findings), max_str_len=10_000)
    if not isinstance(plan, list):
        return []
    removals = [item for item in plan if item.get("is_malicious")]
    upgrades = [item for item in plan if item.get("fix") and not item.get("is_malicious")]
    return removals + upgrades


def _headline(item: dict[str, Any]) -> str:
    count = len(item.get("vulns") or [])
    advisories = f"{count} {'advisory' if count == 1 else 'advisories'}"
    if item.get("is_malicious"):
        verb = "Confirm or remove" if item.get("suspected") else "Remove"
        return f"{verb} {item['package']} ({item.get('reason') or 'known malicious package'}; {advisories})"
    return f"Upgrade {item['package']} {item['current']} → {item['fix']} (clears {advisories}, {item['priority']})"


def top_fix_lines(report: AIBOMReport, *, limit: int = TOP_FIX_LIMIT) -> list[str]:
    """Plain lines for the highest-ranked fixes; empty when nothing has a fix."""
    actionable = _actionable(report)
    if not actionable:
        return []
    shown = actionable[:limit]
    lines = [f"Top fixes ({len(shown)} of {len(actionable)} actionable):"]
    for index, item in enumerate(shown, 1):
        lines.append(f"{index}. {_headline(item)}")
        if item.get("command"):
            lines.append(f"   {item['command']}")
    return lines


def print_top_fixes(con: Any, report: AIBOMReport, *, report_path: str, scan_target: str) -> None:
    """Print the top fixes and one next step after a report is written to a file."""
    lines = top_fix_lines(report)
    if not lines:
        return
    con.print()
    con.print(f"  [bold]{escape(lines[0])}[/bold]")
    for line in lines[1:]:
        con.print(f"    {escape(line)}", soft_wrap=True)
    con.print(
        f"  [green]→[/green] Next: open {escape(report_path)} for the full report, or run "
        f"[bold]agent-bom scan {escape(scan_target)} --remediate remediation.md[/bold] for every fix.",
        soft_wrap=True,
    )
