"""Name the way to get more detail that the running command actually accepts.

Scan output and scanner warnings point the user at ``--verbose``, but many
commands do not take that flag. The hint names ``--verbose`` only when the
command the user typed has it, and otherwise the log-level variable every
command honours.
"""

from __future__ import annotations

from typing import Optional

import click

DEBUG_ENV_HINT = "AGENT_BOM_LOG_LEVEL=DEBUG"


def _accepts_verbose(command: click.Command) -> bool:
    return any("--verbose" in getattr(param, "opts", ()) for param in command.params)


def typed_context(ctx: click.Context) -> click.Context:
    """The context of the command the user typed, not one it forwarded into."""
    chain: list[click.Context] = []
    current: Optional[click.Context] = ctx
    while current is not None:
        chain.append(current)
        current = current.parent
    chain.reverse()
    typed = chain[0]
    for child in chain[1:]:
        if typed.invoked_subcommand != child.info_name or not isinstance(typed.command, click.Group):
            break
        typed = child
    return typed


def verbose_hint(ctx: Optional[click.Context] = None) -> str:
    """``--verbose`` when the typed command accepts it, else the debug log variable."""
    ctx = ctx or click.get_current_context(silent=True)
    if ctx is not None and _accepts_verbose(typed_context(ctx).command):
        return "--verbose"
    return DEBUG_ENV_HINT


def argv_command(group: click.Command, args: list[str]) -> click.Command:
    """Resolve the command an argv names, for hints printed after Click has exited."""
    cmd = group
    for arg in args:
        if arg.startswith("-") or not isinstance(cmd, click.Group):
            continue
        found = cmd.get_command(click.Context(cmd), arg)
        if found is None:
            break
        cmd = found
    return cmd


def command_accepts_verbose(command: click.Command) -> bool:
    return _accepts_verbose(command)


__all__ = ["DEBUG_ENV_HINT", "argv_command", "command_accepts_verbose", "typed_context", "verbose_hint"]
