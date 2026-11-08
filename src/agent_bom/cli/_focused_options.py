"""Options shared by the focused scan commands (`image`, `fs`, `iac`, `sbom`) and the cloud shortcuts."""

from __future__ import annotations

from typing import Optional

import click

from agent_bom.cli._scan_help import AliasedChoice
from agent_bom.cli.options_image import image_supply_chain_options
from agent_bom.cli.options_sources import SCAN_OUTPUT_FORMAT_ALIASES, SCAN_OUTPUT_FORMATS

verbose_option = click.option("--verbose", "-v", is_flag=True, help="Full output: all findings, the full plan and debug logging.")


def _scan_format_option():
    """`-f/--format` validated against the same formats the `scan` command accepts.

    A bad ``-f`` is rejected with rc=2 (like `scan`), instead of being accepted
    as a free string that silently bypasses the default fail-on-severity gate.
    """
    return click.option(
        "-f",
        "--format",
        "output_format",
        type=AliasedChoice(SCAN_OUTPUT_FORMATS, aliases=SCAN_OUTPUT_FORMAT_ALIASES),
        default="console",
        help="Output format",
    )


def _validate_json_or_console_format(command_name: str, output_format: str) -> str:
    """Focused intelligence commands do not emit SARIF or implement vuln gates."""
    normalized = output_format.lower()
    if normalized not in {"console", "json"}:
        raise click.ClickException(
            f"{command_name} supports only format=console or format=json; "
            "SARIF output and vulnerability gates are not supported for this focused mode."
        )
    return normalized


def _focused_default_output(output_format: str, output_path: Optional[str]) -> Optional[str]:
    """Focused scan JSON/SARIF modes stream by default instead of creating a report file."""
    if output_path is None and output_format.lower() in {"json", "sarif"}:
        return "-"
    return output_path


def _image_supply_chain_options(fn):
    for option in reversed(image_supply_chain_options(short_aliases=True)):
        fn = option(fn)
    return fn
