"""Console output for coverage warnings that are not vulnerability-data gaps."""

from __future__ import annotations

from rich.markup import escape
from rich.panel import Panel

from agent_bom.coverage import is_graph_analysis_gap, is_scan_note


def print_graph_coverage_gaps(console, warnings: list) -> list:  # noqa: ANN001
    """Print graph-evaluator gaps in their own panel; return the other warnings.

    Graph gaps are not vulnerability-data gaps, so they must not render with the
    package/advisory wording of the vulnerability coverage panel.
    """
    gaps = [w for w in warnings if is_graph_analysis_gap(w)]
    if gaps:
        body = "\n".join(
            f"[bold yellow]⚠ {escape(str(w.get('ecosystem', 'graph')))}[/bold yellow] — {escape(str(w.get('detail', '')))}" for w in gaps
        )
        body += "\n\n[dim]A graph evaluator stopped at a safety bound; graph-derived findings may UNDER-report.[/dim]"
        console.print(Panel.fit(body, title="[bold red]Incomplete graph analysis[/bold red]", border_style="red"))
    return [w for w in warnings if not is_graph_analysis_gap(w)]


def print_scan_notes(console, warnings: list) -> list:  # noqa: ANN001
    """Print informational scan-run notes; return the remaining (gap) warnings."""
    notes = [w for w in warnings if is_scan_note(w)]
    for note in notes:
        console.print(f"[dim]ℹ {escape(str(note.get('detail', '')))}[/dim]")
    return [w for w in warnings if not is_scan_note(w)]
