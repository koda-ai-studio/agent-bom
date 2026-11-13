"""A command mapping that imports each top-level command only when it is used.

``main.commands`` keeps behaving like the dict Click expects (``in``, ``[]``,
``items()``, assignment), but a lookup is what imports the command's module.
Listing names and rendering top-level help read the static index instead.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator, Mapping, MutableMapping

import click

from agent_bom.cli._command_index import CommandEntry


def resolve_loader(loader: str) -> click.Command:
    """Import ``module:attr``; call it when it is a loader function, not a command."""
    module_name, _, attr = loader.partition(":")
    target = getattr(importlib.import_module(module_name), attr)
    command = target if isinstance(target, click.Command) else target()
    if not isinstance(command, click.Command):
        raise TypeError(f"{loader} did not produce a click command")
    return command


class LazyCommands(MutableMapping[str, click.Command]):
    def __init__(self, index: Mapping[str, CommandEntry]) -> None:
        self._index = dict(index)
        self._loaded: dict[str, click.Command] = {}

    def __getitem__(self, name: str) -> click.Command:
        if name in self._loaded:
            return self._loaded[name]
        entry = self._index[name]
        command = resolve_loader(entry.loader)
        self._loaded[name] = command
        return command

    def __setitem__(self, name: str, command: click.Command) -> None:
        self._loaded[name] = command

    def __delitem__(self, name: str) -> None:
        found = self._index.pop(name, None) is not None
        found = self._loaded.pop(name, None) is not None or found
        if not found:
            raise KeyError(name)

    def __iter__(self) -> Iterator[str]:
        yield from self._index
        yield from (name for name in self._loaded if name not in self._index)

    def __len__(self) -> int:
        return len(self._index.keys() | self._loaded.keys())

    def __contains__(self, name: object) -> bool:
        return name in self._index or name in self._loaded

    def help_row(self, name: str, limit: int) -> tuple[str, bool]:
        """Return ``(short help, hidden)`` without importing an unloaded command."""
        if name in self._loaded:
            command = self._loaded[name]
            return command.get_short_help_str(limit=limit), command.hidden
        entry = self._index[name]
        return entry.short_help, entry.hidden
