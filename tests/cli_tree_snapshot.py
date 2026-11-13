"""Fingerprint the full Click command tree so lazy loading can be proven lossless.

Each command path maps to a digest of its own name, help, flags and options
(subcommands get their own entries). Refresh the fixture after an intentional
CLI change with ``python tests/cli_tree_snapshot.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import click


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if callable(value):
        return "<callable>"
    return repr(value).replace(str(Path.home()), "~")


def _param(param: click.Parameter) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": param.name,
        "kind": type(param).__name__,
        "opts": list(param.opts),
        "secondary_opts": list(param.secondary_opts),
        "type": param.type.name,
        "choices": list(getattr(param.type, "choices", []) or []),
        "required": param.required,
        "nargs": param.nargs,
        "multiple": param.multiple,
        "envvar": _jsonable(param.envvar),
    }
    if isinstance(param, click.Option):
        entry.update(
            {
                "help": param.help,
                "hidden": param.hidden,
                "is_flag": param.is_flag,
                "count": param.count,
                "show_default": _jsonable(param.show_default),
                "default": _jsonable(param.default),
            }
        )
    return entry


FIXTURE = Path(__file__).parent / "fixtures" / "cli_command_tree.json"


def _describe(command: click.Command) -> dict[str, Any]:
    return {
        "name": command.name,
        "hidden": command.hidden,
        "deprecated": _jsonable(command.deprecated),
        "help": command.help,
        "short_help": command.short_help,
        "epilog": command.epilog,
        "params": [_param(param) for param in command.params],
        "group": isinstance(command, click.Group),
    }


def snapshot(command: click.Command, path: str = "agent-bom", ctx: click.Context | None = None) -> dict[str, str]:
    """Map every command path under ``command`` to a digest of its own surface."""
    encoded = json.dumps(_describe(command), sort_keys=True).encode()
    tree = {path: hashlib.sha256(encoded).hexdigest()[:16]}
    if isinstance(command, click.Group):
        sub_ctx = click.Context(command, parent=ctx, info_name=command.name)
        for name in command.list_commands(sub_ctx):
            sub = command.get_command(sub_ctx, name)
            if sub is not None:
                tree.update(snapshot(sub, f"{path} {name}", sub_ctx))
    return tree


if __name__ == "__main__":
    from agent_bom.cli import main

    FIXTURE.write_text(json.dumps(snapshot(main), indent=1, sort_keys=True) + "\n", encoding="utf-8")
