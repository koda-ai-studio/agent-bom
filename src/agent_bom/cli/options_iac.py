"""IaC exception and policy options for the focused ``iac`` command."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import click


def iac_control_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    """``--ignore-file`` and ``--policy``: accepted exceptions and allow/warn/block rules for IaC findings."""
    fn = click.option(
        "--policy",
        "policy",
        default=None,
        metavar="PATH",
        help="Policy file whose IaC rules allow, warn or block findings by rule, resource and environment.",
    )(fn)
    return click.option(
        "--ignore-file",
        "ignore_file",
        default=None,
        metavar="PATH",
        help="Exceptions file (default: .agent-bom-ignore.yaml). IaC entries need a rule and a reason; see Exceptions and policy for IaC.",
    )(fn)
