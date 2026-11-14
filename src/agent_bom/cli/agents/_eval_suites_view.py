"""Console summary of eval suites found by the AI-inventory source scan."""

from __future__ import annotations

from collections import Counter
from typing import Any


def eval_summary_lines(eval_suites: list[dict[str, Any]], coverage: dict[str, Any] | None) -> list[str]:
    """Plain lines naming what the eval search covered and what it found; empty when it did not run."""
    if not isinstance(coverage, dict):
        return []
    suites = [suite for suite in eval_suites if isinstance(suite, dict)]
    files = int(coverage.get("files_examined") or 0)
    if coverage.get("status") != "complete":
        detail = str(coverage.get("detail") or "a limit was reached")
        return [f"Eval suites: search incomplete ({detail}); eval coverage findings are not raised for this scan"]
    if not suites:
        return [f"Eval suites: none found in the scanned project files ({files} candidate files read)"]
    purposes = Counter(str(suite.get("purpose") or "unknown") for suite in suites)
    linked = sum(1 for suite in suites if suite.get("link_status") == "linked")
    harnesses = ", ".join(sorted({str(suite.get("harness") or "") for suite in suites} - {""}))
    return [
        f"Eval suites: {len(suites)} found ({harnesses}) — {purposes['safety']} safety, {purposes['quality']} quality, "
        f"{purposes['unknown']} purpose unknown; {linked} linked to an agent or model, {len(suites) - linked} unlinked"
    ]


def print_eval_summary(console: Any, eval_suites: list[dict[str, Any]], coverage: dict[str, Any] | None) -> None:
    for line in eval_summary_lines(eval_suites, coverage):
        console.print(f"  [cyan]{line}[/cyan]", highlight=False)
