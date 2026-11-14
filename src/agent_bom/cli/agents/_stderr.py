"""Stderr notices that stay one JSON object per line under ``--log-json``."""

from __future__ import annotations

import logging
from typing import Any

import click
from rich.console import Console

from agent_bom.core.progress_log import PROGRESS_LOGGER, configure_progress_logging, progress_log_console
from agent_bom.logging_config import json_logging_active, json_logging_requested, setup_logging

_logger = logging.getLogger("agent_bom.cli")


def stderr_notice(message: str, *, level: int = logging.ERROR, prefix: str = "agent-bom: ") -> None:
    """Write a notice to stderr, or log it as a structured record when logs are JSON."""
    if json_logging_active():
        logging.getLogger(PROGRESS_LOGGER if level < logging.WARNING else _logger.name).log(level, message)
        return
    click.echo(f"{prefix}{message}", err=True)


VERDICT_LOGGER = "agent_bom.verdict"


def log_record(message: str, *, level: int, context: dict[str, Any], logger_name: str = _logger.name) -> None:
    """Emit one JSON log record whose ``context`` carries the structured fields.

    The verdict logger is pinned to INFO so a PASS verdict still prints under
    ``-q``, where the rest of agent_bom stays at WARNING.
    """
    logger = logging.getLogger(logger_name)
    if logger_name == VERDICT_LOGGER:
        logger.setLevel(logging.INFO)
    logger.log(level, message, extra={"context": context})


def stderr_console(*, quiet: bool, log_json: bool) -> Console:
    """The progress console for a command that does not run the scan pipeline's logging setup.

    Under JSON logging (the flag or ``AGENT_BOM_LOG_JSON``) progress becomes
    ``agent_bom.progress`` records; ``quiet`` silences it either way.
    """
    if json_logging_requested(log_json):
        setup_logging(json_output=True)
        configure_progress_logging(enabled=not quiet)
        if not quiet:
            return progress_log_console()
    return Console(stderr=True, quiet=quiet)


__all__ = ["VERDICT_LOGGER", "log_record", "stderr_console", "stderr_notice"]
