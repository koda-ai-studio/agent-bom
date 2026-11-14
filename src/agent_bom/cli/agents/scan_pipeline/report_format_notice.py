"""Tell a person at a terminal that the JSON report's default schema changes in 0.116.0.

CI jobs, ``--log-json``, ``-q`` and agent mode never see it, and neither does a
caller that already chose ``--report-format`` (or ``AGENT_BOM_REPORT_FORMAT``).
"""

from __future__ import annotations

import os
import sys
from typing import Any

import click

from agent_bom.ci_detect import is_ci
from agent_bom.cli._param_source import is_explicit

NOTICE = (
    "agent-bom: this JSON report uses schema 1.0; 0.116.0 makes schema 2.0 (shared records written once, "
    "referenced by ID) the default. Pass --report-format v2 to adopt it now, or --report-format v1 to keep 1.0."
)


def _interactive() -> bool:
    try:
        return bool(sys.stderr.isatty()) and not is_ci()
    except (AttributeError, ValueError):
        return False


def _format_chosen() -> bool:
    return is_explicit(click.get_current_context(silent=True), "report_format")


def _writes_json_file(opts: Any) -> bool:
    output = str(getattr(opts, "output", "") or "")
    if not output or output == "-" or os.path.realpath(output) == os.path.realpath(os.devnull):
        return False
    return str(getattr(opts, "output_format", "")).lower() == "json"


def notice_report_schema_default(opts: Any) -> None:
    """Print the one-line notice to stderr when an interactive ``-f json`` scan wrote a file."""
    if getattr(opts, "quiet", False) or getattr(opts, "log_json", False) or getattr(opts, "agent_mode", False):
        return
    if _writes_json_file(opts) and _interactive() and not _format_chosen():
        click.echo(NOTICE, err=True)
