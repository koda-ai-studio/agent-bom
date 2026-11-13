"""The source-analysis budget a default ``scan`` runs under.

A first scan of a large repository spent minutes in code analysis, the
secret scan and the AI-component scan, each of which reads every eligible
file. The default ``scan`` path therefore stops each of them after a fixed
number of files, in a deterministic order, and records the stop as a coverage
gap that names ``--full-analysis``. Only ``scan`` sets a budget: explicit
commands (``secrets``, ``code``) and API scans keep their own ceilings.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

FULL_ANALYSIS_HINT = "run `agent-bom scan --full-analysis` to analyse every file"


@dataclass(frozen=True)
class SourceBudget:
    """Files each source scanner may read before it stops and reports partial coverage."""

    code_analysis_files: int = 500
    secret_files: int = 1_000
    ai_component_files: int = 1_000


DEFAULT_SOURCE_BUDGET = SourceBudget()


@dataclass
class _BudgetScope:
    budget: SourceBudget | None
    stops: dict[str, str] = field(default_factory=dict)


_scope: ContextVar[_BudgetScope | None] = ContextVar("source_budget", default=None)


def current_source_budget() -> SourceBudget | None:
    """The budget of the running ``scan``, or None when no budget applies."""
    scope = _scope.get()
    return scope.budget if scope is not None else None


@contextmanager
def source_budget_scope(budget: SourceBudget | None) -> Iterator[None]:
    token = _scope.set(_BudgetScope(budget))
    try:
        yield
    finally:
        _scope.reset(token)


def budget_stop_detail(scanner: str, analysed: int, eligible: int | None = None) -> str:
    """Coverage-gap text for a scanner that stopped at the budget; also kept for the console summary."""
    files = f"{analysed:,} of {eligible:,}" if eligible is not None else f"the first {analysed:,}"
    scope = _scope.get()
    if scope is not None:
        scope.stops[scanner] = f"{scanner.lower()} {files} files"
    return f"{scanner} stopped at the default scan budget after {files} files; {FULL_ANALYSIS_HINT}."


def budget_stop_summary() -> str | None:
    """One line naming every scanner the budget stopped in this scan, or None."""
    scope = _scope.get()
    if scope is None or not scope.stops:
        return None
    return f"Source analysis stopped at the default scan budget ({'; '.join(scope.stops.values())}); {FULL_ANALYSIS_HINT}."
