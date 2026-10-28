"""Confirm a written report artifact on stdout.

Scan diagnostics render on a stderr console so ``agent-bom scan > report.txt``
captures only the report. When the report itself goes to a file (``-o``, or a
saved profile that pins ``format=json``), stdout would otherwise stay empty and
a first run looks like it produced nothing. The confirmation line therefore
goes to stdout, and only there, so interactive terminals see it once.
"""

from __future__ import annotations

from typing import Any

import click


def announce_report_written(con: Any, label: str, path: Any, *, quiet: bool = False) -> None:
    """Print ``✓ <label> written to <path>`` on stdout unless the run is quiet."""
    if quiet or bool(getattr(con, "quiet", False)):
        return
    click.echo(f"\n  ✓ {label} written to {path}")


__all__ = ["announce_report_written"]
