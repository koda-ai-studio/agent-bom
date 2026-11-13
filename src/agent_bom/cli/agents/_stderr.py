"""Stderr notices that stay one JSON object per line under ``--log-json``."""

from __future__ import annotations

import logging

import click

from agent_bom.core.progress_log import PROGRESS_LOGGER
from agent_bom.logging_config import json_logging_active

_logger = logging.getLogger("agent_bom.cli")


def stderr_notice(message: str, *, level: int = logging.ERROR, prefix: str = "agent-bom: ") -> None:
    """Write a notice to stderr, or log it as a structured record when logs are JSON."""
    if json_logging_active():
        logging.getLogger(PROGRESS_LOGGER if level < logging.WARNING else _logger.name).log(level, message)
        return
    click.echo(f"{prefix}{message}", err=True)


__all__ = ["stderr_notice"]
