"""CLI errors as single JSON log records when JSON logging is requested.

The request is read from argv and ``AGENT_BOM_LOG_JSON`` before Click parses,
because a usage error can stop parsing before ``--log-json`` is processed.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import IO, Any

import click

from agent_bom.logging_config import JSONFormatter, json_logging_requested
from agent_bom.security import sanitize_text

_LOGGER = "agent_bom.cli"


def json_errors_requested(args: Sequence[str]) -> bool:
    """True when ``--log-json`` appears before any ``--`` separator, or the env var asks for JSON logs."""
    options = list(args)
    if "--" in options:
        options = options[: options.index("--")]
    return "--log-json" in options or json_logging_requested(None)


def emit_json_error(message: str, *, exit_code: int, error_type: str, command: str | None = None) -> None:
    """Write one ERROR record as a JSON line on stderr, whatever handlers are configured."""
    record = logging.LogRecord(_LOGGER, logging.ERROR, __file__, 0, message, None, None)
    context: dict[str, Any] = {"exit_code": exit_code, "error_type": error_type}
    if command:
        context["command"] = command
    record.context = context
    sys.stderr.write(JSONFormatter().format(record) + "\n")
    sys.stderr.flush()


@contextmanager
def json_click_errors(command: str | None) -> Iterator[None]:
    """Render Click's error output as JSON records while keeping Click's exit codes."""
    originals = (click.ClickException.show, click.UsageError.show)

    def show(self: click.ClickException, file: IO[Any] | None = None) -> None:
        error_type = "usage" if isinstance(self, click.UsageError) else "error"
        emit_json_error(sanitize_text(self.format_message()), exit_code=self.exit_code, error_type=error_type, command=command)

    click.ClickException.show = show  # type: ignore[method-assign]
    click.UsageError.show = show  # type: ignore[method-assign]
    try:
        yield
    finally:
        click.ClickException.show, click.UsageError.show = originals  # type: ignore[method-assign]


__all__ = ["emit_json_error", "json_click_errors", "json_errors_requested"]
