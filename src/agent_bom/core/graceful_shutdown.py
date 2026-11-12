"""Shutdown signalling for the API process.

Uvicorn's own SIGTERM handler stops the listener and waits for in-flight
requests, and the application lifespan only learns of the shutdown after that
wait. Wrapping the handler lets readiness report draining from the moment the
signal arrives, and ``graceful_shutdown_seconds`` bounds the in-flight wait so
the lifespan drain still fits inside the pod's termination grace period.
"""

from __future__ import annotations

import signal
import threading
from types import FrameType
from typing import Any

from agent_bom.core.settings import env_int

_DEFAULT_GRACEFUL_SHUTDOWN_SECONDS = 10
_termination_requested = False


def graceful_shutdown_seconds() -> int:
    """Seconds uvicorn waits for in-flight requests after SIGTERM."""
    return env_int(
        "AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS",
        _DEFAULT_GRACEFUL_SHUTDOWN_SECONDS,
        minimum=0,
        on_invalid="default",
    )


def termination_requested() -> bool:
    return _termination_requested


def install_sigterm_drain() -> None:
    """Record SIGTERM before handing it to the handler already installed (uvicorn's)."""
    if threading.current_thread() is not threading.main_thread():
        return
    previous: Any = signal.getsignal(signal.SIGTERM)
    if getattr(previous, "_agent_bom_drain", False):
        return

    def _on_sigterm(signum: int, frame: FrameType | None) -> None:
        global _termination_requested
        _termination_requested = True
        if callable(previous):
            previous(signum, frame)
        elif previous == signal.SIG_DFL:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.raise_signal(signum)

    _on_sigterm._agent_bom_drain = True  # type: ignore[attr-defined]
    signal.signal(signal.SIGTERM, _on_sigterm)
