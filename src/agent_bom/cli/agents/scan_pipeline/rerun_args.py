"""The scan inputs a follow-up command repeats: what the user typed, minus the output choice."""

from __future__ import annotations

import shlex
from typing import Any

import click
from click.core import ParameterSource

# The footer supplies its own format and destination; these only shape this run's output.
_REPLACED = frozenset({"output", "output_format", "quiet", "open_report"})
_SECRET_MARKERS = ("pass", "secret", "token", "key", "credential")


def _is_secret(param: click.Parameter) -> bool:
    name = (param.name or "").lower()
    return any(marker in name for marker in _SECRET_MARKERS)


def _tokens(param: click.Parameter, value: Any) -> list[str]:
    if isinstance(param, click.Argument):
        values = value if isinstance(value, (tuple, list)) else (value,)
        return [str(item) for item in values if item is not None]
    option = param if isinstance(param, click.Option) else None
    if option is None or not option.opts:
        return []
    if option.is_flag and not option.count:
        if value:
            return [option.opts[0]]
        return [option.secondary_opts[0]] if option.secondary_opts else []
    if option.count:
        return [option.opts[0]] * int(value or 0)
    values = value if option.multiple and isinstance(value, (tuple, list)) else (value,)
    return [token for item in values if item is not None for token in (option.opts[0], str(item))]


def typed_scan_arguments(ctx: click.Context | None = None) -> str | None:
    """Shell-quoted scan arguments given on the command line; None outside a scan command.

    Options from the environment or defaults are not repeated, nor any option whose
    name marks it as a secret, so the footer never prints a credential.
    """
    ctx = ctx or click.get_current_context(silent=True)
    if ctx is None or ctx.command.name != "scan":
        return None
    tokens: list[str] = []
    for param in ctx.command.params:
        name = param.name or ""
        if name in _REPLACED or _is_secret(param) or ctx.get_parameter_source(name) is not ParameterSource.COMMANDLINE:
            continue
        tokens += _tokens(param, ctx.params.get(name))
    return shlex.join(tokens)
