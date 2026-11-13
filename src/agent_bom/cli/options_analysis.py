"""Scan options that set how much source analysis runs and how much of it the report lists."""

from __future__ import annotations

import click

from agent_bom.cli.options_helpers import _apply


def analysis_scope_options(fn):
    """``--full-analysis`` lifts the default source budget; ``--include-code-graph`` lists relationship rows."""
    return _apply(
        [
            click.option(
                "--full-analysis",
                "full_analysis",
                is_flag=True,
                default=False,
                help="Run code analysis, the secret scan and the AI-component scan over every eligible file. "
                "This is already the default for CI, non-interactive output, gates and machine-readable formats; "
                "an interactive scan otherwise stops each after 500, 1,000 and 1,000 files and marks coverage incomplete.",
            ),
            click.option(
                "--quick",
                "quick",
                is_flag=True,
                default=False,
                help="Stop code analysis, the secret scan and the AI-component scan after 500, 1,000 and 1,000 files, "
                "even in CI or with a gate. The report marks coverage incomplete, so an otherwise clean scan exits non-zero.",
            ),
            click.option(
                "--include-code-graph",
                "include_code_graph",
                is_flag=True,
                default=False,
                help="List every call-graph, control-flow and dependency-reach row from code analysis in the report. "
                "By default the report carries their counts only (large repositories produce hundreds of thousands of rows).",
            ),
        ]
    )(fn)
