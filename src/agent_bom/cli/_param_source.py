"""Parameter sources that survive ``ctx.invoke`` forwarding.

Click's ``Context.invoke`` builds the target context without recording where
forwarded values came from, so ``get_parameter_source`` returns ``None`` and an
explicit ``--format console`` on ``agent-bom image`` looks like the default.
``invoke_forwarding`` records the caller's sources in the shared ``ctx.meta``
for the invoked command, and ``parameter_source`` reads them back.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import click
from click.core import ParameterSource

EXPLICIT_SOURCES = frozenset({ParameterSource.COMMANDLINE, ParameterSource.ENVIRONMENT})
_META_KEY = "agent_bom.forwarded_parameter_sources"
_DEFAULT_ALIASES = {"output": "output_path"}


def _caller_source(ctx: click.Context, name: str, aliases: Mapping[str, str], value: Any) -> ParameterSource:
    caller_params = {param.name for param in ctx.command.params}
    caller_name = aliases.get(name, name)
    caller_name = caller_name if caller_name in caller_params else name
    if caller_name in caller_params:
        return parameter_source(ctx, caller_name) or ParameterSource.DEFAULT
    # A value the forwarding command fixed itself is a deliberate choice; an unset one is not.
    return ParameterSource.DEFAULT if value is None else ParameterSource.COMMANDLINE


def invoke_forwarding(
    ctx: click.Context,
    command: click.Command,
    *,
    aliases: Mapping[str, str] | None = None,
    **kwargs: Any,
) -> Any:
    """``ctx.invoke(command, **kwargs)`` keeping each forwarded value's source.

    ``aliases`` maps a target parameter name to the caller's parameter name when
    they differ; ``output`` -> ``output_path`` is assumed.
    """
    names = {**_DEFAULT_ALIASES, **(aliases or {})}
    sources = {name: _caller_source(ctx, name, names, value) for name, value in kwargs.items()}
    stack = ctx.meta.setdefault(_META_KEY, [])
    stack.append((command, sources))
    try:
        return ctx.invoke(command, **kwargs)
    finally:
        stack.pop()


def parameter_source(ctx: click.Context | None, name: str) -> ParameterSource | None:
    """Click's source for ``name``, or the forwarding caller's when Click has none."""
    if ctx is None:
        return None
    source = ctx.get_parameter_source(name)
    if source is not None:
        return source
    for command, sources in reversed(ctx.meta.get(_META_KEY, [])):
        if command is ctx.command:
            return sources.get(name)
    return None


def is_explicit(ctx: click.Context | None, name: str) -> bool:
    return parameter_source(ctx, name) in EXPLICIT_SOURCES
