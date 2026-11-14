"""Centralized logging configuration for agent-bom.

Usage in any module:
    import logging
    logger = logging.getLogger(__name__)  # already standard

CLI / entrypoint:
    from agent_bom.logging_config import setup_logging
    setup_logging(level="DEBUG", json_output=True)

Environment variables:
    AGENT_BOM_LOG_LEVEL  — DEBUG, INFO, WARNING, ERROR (default: WARNING)
    AGENT_BOM_LOG_JSON   — 1 to enable JSON structured output
    AGENT_BOM_LOG_FILE   — path to write log file (in addition to stderr)
"""

import json
import logging
import os
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Optional, TypeVar

from agent_bom.core.settings import env_flag, env_str

_T = TypeVar("_T")


class AccessLogPathFilter(logging.Filter):
    """Omit queries from Uvicorn access records before any handler formats them."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) == 5:
            client, method, target, version, status = record.args
            if isinstance(target, str):
                record.args = (client, method, target.split("?", 1)[0].split("#", 1)[0], version, status)
        return True


_JSON_FORMATTER = {"()": "agent_bom.logging_config.JSONFormatter"}


def json_logging_requested(flag: Optional[bool] = None) -> bool:
    """JSON logs when the flag is set, otherwise when ``AGENT_BOM_LOG_JSON`` asks for them."""
    return bool(flag) or env_flag("AGENT_BOM_LOG_JSON")


def logging_configured() -> bool:
    """Whether ``setup_logging`` already gave the agent_bom logger its handlers."""
    return bool(logging.getLogger("agent_bom").handlers)


@contextmanager
def owned_library_logging(library: str) -> Iterator[None]:
    """Keep a library's logging setup out of the root logger and send its records through agent-bom's handlers.

    The MCP SDK's server constructor calls ``logging.basicConfig`` with a Rich
    handler. With agent_bom records propagating to root, every line then
    printed twice, and the SDK's own records ignored ``--log-json``.
    """
    root = logging.getLogger()
    handlers_before, level_before = list(root.handlers), root.level
    try:
        yield
    finally:
        for handler in [h for h in root.handlers if h not in handlers_before]:
            root.removeHandler(handler)
        root.setLevel(level_before)
        owner = logging.getLogger("agent_bom")
        if owner.handlers:
            library_logger = logging.getLogger(library)
            library_logger.handlers = list(owner.handlers)
            library_logger.setLevel(owner.level)
            library_logger.propagate = False


def with_owned_logging(library: str, factory: Callable[..., _T]) -> Callable[..., _T]:
    """Wrap ``factory`` so ``library``'s logging setup during the call stays under agent-bom's handlers."""

    def call(*args: Any, **kwargs: Any) -> _T:
        with owned_library_logging(library):
            return factory(*args, **kwargs)

    return call


def json_logging_active() -> bool:
    """Whether ``setup_logging`` configured the agent_bom logger for JSON."""
    return any(isinstance(handler.formatter, JSONFormatter) for handler in logging.getLogger("agent_bom").handlers)


def api_log_config(
    default_config: dict[str, Any],
    *,
    json_output: Optional[bool] = None,
    level: Optional[str] = None,
) -> dict[str, Any]:
    """Keep Uvicorn's logging behavior without retaining query credentials.

    With JSON requested, Uvicorn's server and access records use the JSON
    formatter, and the root logger does too so that worker processes, which do
    not run ``setup_logging``, never fall back to plain text.
    """
    config = deepcopy(default_config)
    config.setdefault("filters", {})["access_path"] = {"()": "agent_bom.logging_config.AccessLogPathFilter"}
    config["handlers"]["access"].setdefault("filters", []).append("access_path")
    if json_logging_requested(json_output):
        config["formatters"] = {"default": dict(_JSON_FORMATTER), "access": dict(_JSON_FORMATTER)}
        config["root"] = {"handlers": ["default"], "level": (level or env_str("AGENT_BOM_LOG_LEVEL", "WARNING")).upper()}
    return config


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for production / SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "context"):
            entry["context"] = record.context
        http = getattr(record, "http", None)
        if isinstance(http, dict):
            entry["http"] = http
        elif record.name == "uvicorn.access" and isinstance(record.args, tuple) and len(record.args) == 5:
            client, method, path, version, status = record.args
            entry["http"] = {"client": client, "method": method, "path": path, "version": version, "status": status}
        return json.dumps(entry, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable colored formatter for terminal output."""

    COLORS = {
        "DEBUG": "\033[36m",  # cyan
        "INFO": "\033[32m",  # green
        "WARNING": "\033[33m",  # yellow
        "ERROR": "\033[31m",  # red
        "CRITICAL": "\033[1;31m",  # bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if color else ""
        record.levelname = f"{color}{record.levelname:<8}{reset}"
        return super().format(record)


def setup_logging(
    level: Optional[str] = None,
    json_output: Optional[bool] = None,
    log_file: Optional[str] = None,
) -> None:
    """Configure logging for all agent-bom modules.

    Args:
        level: Log level (DEBUG/INFO/WARNING/ERROR). Falls back to
            AGENT_BOM_LOG_LEVEL env var, then WARNING.
        json_output: Use JSON structured format. Falls back to
            AGENT_BOM_LOG_JSON env var.
        log_file: Path to log file. Falls back to AGENT_BOM_LOG_FILE env var.
    """
    level = level or os.environ.get("AGENT_BOM_LOG_LEVEL", "WARNING")
    # CLI flags pass False when unset; the environment still turns JSON on.
    json_output = json_logging_requested(json_output)
    log_file = log_file or os.environ.get("AGENT_BOM_LOG_FILE")

    root = logging.getLogger("agent_bom")
    root.setLevel(getattr(logging, (level or "WARNING").upper(), logging.WARNING))
    # Under JSON the server also gives the root logger a JSON handler; stop
    # agent_bom records reaching it twice.
    root.propagate = not json_output

    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()

    # Stderr handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    if json_output:
        stderr_handler.setFormatter(JSONFormatter())
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
        datefmt = "%H:%M:%S"
        if sys.stderr.isatty():
            stderr_handler.setFormatter(ConsoleFormatter(fmt=fmt, datefmt=datefmt))
        else:
            stderr_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(stderr_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        os.chmod(log_file, 0o600)
        file_handler.setFormatter(JSONFormatter())
        root.addHandler(file_handler)

    # Quiet noisy third-party loggers
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def ensure_logging(level: Optional[str] = None) -> None:
    """Configure logging unless a caller already did, keeping their handlers and format."""
    if not logging_configured():
        setup_logging(level=level)
