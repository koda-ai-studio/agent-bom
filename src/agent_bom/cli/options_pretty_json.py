"""The --pretty-json option shared by commands that write JSON report files."""

from __future__ import annotations

import os

import click

from agent_bom.output.json_writer import PRETTY_JSON_ENV


def _enable_pretty_json(_ctx: click.Context, _param: click.Parameter, value: bool) -> bool:
    if value:
        os.environ[PRETTY_JSON_ENV] = "1"
    return value


PRETTY_JSON_OPTION = click.option(
    "--pretty-json",
    is_flag=True,
    default=False,
    expose_value=False,
    callback=_enable_pretty_json,
    help=(
        "Indent JSON written to a file (-o report.json, CycloneDX, SPDX, SARIF, badge, graph). "
        "Files are compact by default; stdout is always indented. Env: AGENT_BOM_PRETTY_JSON=1."
    ),
)
