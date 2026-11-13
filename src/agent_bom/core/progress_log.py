"""Route rich progress output into structured log records.

Under ``--log-json`` every stderr line must be one JSON object, so the
progress console writes into a stream that turns each rendered line into an
INFO record on the ``agent_bom.progress`` logger instead of plain text.
"""

from __future__ import annotations

import io
import logging
from typing import IO, cast

from rich.console import Console

PROGRESS_LOGGER = "agent_bom.progress"
# Whitespace plus the box-drawing strokes rich uses for rules, so a rule keeps only its title.
_RULE_CHARS = " \t\r─━═"


class ProgressLogStream(io.TextIOBase):
    """Text stream that emits each complete, non-blank line as a log record."""

    def __init__(self, logger_name: str = PROGRESS_LOGGER) -> None:
        super().__init__()
        self._logger = logging.getLogger(logger_name)
        self._pending = ""

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        return False

    def write(self, text: str) -> int:
        self._pending += text
        while "\n" in self._pending:
            line, self._pending = self._pending.split("\n", 1)
            self._emit(line)
        return len(text)

    def flush(self) -> None:
        if self._pending:
            line, self._pending = self._pending, ""
            self._emit(line)

    def _emit(self, line: str) -> None:
        message = line.strip(_RULE_CHARS)
        if message:
            self._logger.info(message)


def progress_log_console() -> Console:
    """A plain-text console whose output becomes ``agent_bom.progress`` records."""
    return Console(
        file=cast(IO[str], ProgressLogStream()),
        force_terminal=False,
        no_color=True,
        highlight=False,
        emoji=False,
        soft_wrap=True,
        width=200,
    )


def configure_progress_logging(*, enabled: bool) -> None:
    """Let progress INFO records through while the rest of agent_bom keeps its level."""
    logging.getLogger(PROGRESS_LOGGER).setLevel(logging.INFO if enabled else logging.NOTSET)


__all__ = ["PROGRESS_LOGGER", "ProgressLogStream", "configure_progress_logging", "progress_log_console"]
