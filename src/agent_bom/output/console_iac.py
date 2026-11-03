"""Console table for IaC misconfiguration findings (`agent-bom iac --format console`)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Any

from rich.markup import escape
from rich.padding import Padding
from rich.table import Table

from agent_bom.core.severity import normalize_severity, severity_worst_first_rank
from agent_bom.models import Severity
from agent_bom.output.console_style import _sev_badge

DEFAULT_IAC_TABLE_LIMIT = 25
_SUMMARY_BANDS = (("critical", "red"), ("high", "yellow"), ("medium", "cyan"), ("low", "dim"))


def _severity(value: str) -> Severity:
    try:
        return Severity(normalize_severity(value))
    except ValueError:
        return Severity.UNKNOWN


def _location(finding: Any) -> str:
    line = int(finding.line_number or 0)
    return f"{finding.file_path}:{line}" if line > 0 else str(finding.file_path)


def _sort_key(finding: Any) -> tuple[int, str, int, str]:
    return (severity_worst_first_rank(finding.severity), str(finding.file_path), int(finding.line_number or 0), finding.rule_id)


def iac_severity_summary(findings: Sequence[Any], *, markup: bool = True) -> str:
    """``2 critical · 1 high · 4 medium`` over every band that has findings."""
    counts = Counter(normalize_severity(finding.severity) for finding in findings)
    parts = []
    for band, style in _SUMMARY_BANDS:
        if counts.get(band):
            text = f"{counts[band]} {band}"
            parts.append(f"[{style}]{text}[/{style}]" if markup else text)
    other = sum(count for band, count in counts.items() if band not in dict(_SUMMARY_BANDS))
    if other:
        parts.append(f"{other} unrated")
    return " · ".join(parts)


def print_iac_findings_table(con: Any, findings: Sequence[Any], *, limit: int | None = DEFAULT_IAC_TABLE_LIMIT) -> None:
    """Severity-sorted findings (severity, rule, file:line, title), capped at ``limit`` rows."""
    if not findings:
        return
    ordered = sorted(findings, key=_sort_key)
    shown = ordered if limit is None else ordered[:limit]
    table = Table(box=None, padding=(0, 2, 0, 0), show_header=True, header_style="bold dim", pad_edge=False, expand=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Location", overflow="fold", ratio=2)
    table.add_column("Title", overflow="fold", ratio=3)
    for finding in shown:
        table.add_row(_sev_badge(_severity(finding.severity)), escape(finding.rule_id), escape(_location(finding)), escape(finding.title))
    con.print()
    con.print(Padding(table, (0, 0, 0, 2)))
    hidden = len(ordered) - len(shown)
    if hidden:
        con.print(f"  [dim]+{hidden} more finding(s) — full list: -f json, or -f sarif -o results.sarif[/dim]")


_NOTICE_STYLE = {
    "expired": "[yellow]⚠ expired[/yellow]",
    "expiring": "[cyan]ℹ expiring[/cyan]",
    "invalid": "[yellow]⚠ invalid[/yellow]",
    "rejected": "[red]✗ rejected[/red]",
}


def print_iac_exceptions(con: Any, suppressed: Sequence[Any], notices: Sequence[Any], *, verbose: bool = False) -> None:
    """``N accepted exception(s)`` plus every expired / expiring / invalid / rejected exception notice."""
    if suppressed or notices:
        con.print()
    if suppressed:
        sources = Counter(str((f.suppression or {}).get("source", "?")) for f in suppressed)
        by_source = ", ".join(f"{source} {count}" for source, count in sorted(sources.items()))
        con.print(f"  [dim]{len(suppressed)} accepted exception(s) ({by_source}) — retained in JSON/SARIF, excluded from gates[/dim]")
        if verbose:
            for finding in sorted(suppressed, key=_sort_key):
                record = finding.suppression or {}
                owner = f" owner={record['owner']}" if record.get("owner") else ""
                expires = f" expires={record['expires']}" if record.get("expires") else ""
                con.print(
                    f"    [dim]{escape(finding.rule_id)} {escape(_location(finding))} — {escape(str(record.get('reason', '')))}"
                    f" ({escape(str(record.get('source')))}{escape(owner)}{escape(expires)})[/dim]"
                )
    for notice in notices:
        con.print(f"  {_NOTICE_STYLE.get(notice.kind, notice.kind)} exception: {escape(notice.message)}")
