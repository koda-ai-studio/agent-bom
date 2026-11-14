"""The --report-format option shared by commands that write JSON reports."""

from __future__ import annotations

import click

REPORT_FORMAT_OPTION = click.option(
    "--report-format",
    "report_format",
    type=click.Choice(["v1", "v2", "legacy"], case_sensitive=False),
    default="v1",
    envvar="AGENT_BOM_REPORT_FORMAT",
    show_default=True,
    help=(
        "JSON report schema. v1 (default; alias legacy) writes schema 1.0 with every record inline. v2 writes schema 2.0, "
        "which writes each compliance control, package, asset and provenance record once and references it by ID; "
        "it becomes the default in 0.116.0. Pushes use 2.0 automatically when the control plane accepts it."
    ),
)
