"""Decide whether a ``scan`` runs under the source budget.

The budget exists so an interactive first scan of a large repository returns in
about a minute. A gate, a CI job or a machine caller must keep analysing every
file, exactly as before the budget existed: an incomplete scan fails closed, so
budgeting it would change its outcome or exit code. Those callers can still opt
in with ``--quick``; ``--full-analysis`` always analyses everything.
"""

from __future__ import annotations

import sys
from typing import Any

from agent_bom.ci_detect import is_ci
from agent_bom.cli._agent_mode import agent_mode_requested
from agent_bom.scan_budget import DEFAULT_SOURCE_BUDGET, SourceBudget

#: Output formats written for pipelines and other tools rather than for a person.
_MACHINE_FORMATS = frozenset({"sarif", "junit", "cyclonedx", "spdx", "spdx2", "csv", "parquet", "prometheus", "badge"})
_GATE_FLAGS = ("fail_on_kev", "fail_on_malicious", "fail_if_ai_risk", "delta_mode")
_GATE_VALUES = ("fail_on_severity", "warn_on_severity", "policy", "baseline", "push_url", "push_gateway")


def _gated(opts: Any) -> bool:
    if any(getattr(opts, name, False) for name in _GATE_FLAGS):
        return True
    if any(getattr(opts, name, None) for name in _GATE_VALUES):
        return True
    return str(getattr(opts, "output_format", "") or "").lower() in _MACHINE_FORMATS


def _interactive() -> bool:
    try:
        tty = sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False
    return tty and not is_ci() and not agent_mode_requested()


def scan_source_budget(opts: Any) -> SourceBudget | None:
    """The budget for this scan: only an interactive, ungated scan or an explicit ``--quick``."""
    if getattr(opts, "full_analysis", False):
        return None
    if getattr(opts, "quick", False):
        return DEFAULT_SOURCE_BUDGET
    if _interactive() and not _gated(opts):
        return DEFAULT_SOURCE_BUDGET
    return None
