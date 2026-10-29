"""Confirm a written report artifact on stdout.

Scan diagnostics render on a stderr console so ``agent-bom scan > report.txt``
captures only the report. When the report itself goes to a file (``-o``, or a
saved profile that pins ``format=json``), stdout would otherwise stay empty and
a first run looks like it produced nothing. The confirmation line goes to
stdout when stdout is an interactive terminal, so the first run shows where the
report went; when stdout is a pipe or file it goes to stderr, so ``-o`` keeps
stdout empty for callers that read it.
"""

from __future__ import annotations

import sys
from typing import Any

import click


def announce_report_written(con: Any, label: str, path: Any, *, quiet: bool = False) -> None:
    """Print ``✓ <label> written to <path>`` (stdout on a terminal, else stderr) unless quiet."""
    if quiet or bool(getattr(con, "quiet", False)):
        return
    interactive = bool(getattr(sys.stdout, "isatty", lambda: False)())
    click.echo(f"\n  ✓ {label} written to {path}", err=not interactive)


__all__ = ["announce_report_written"]
