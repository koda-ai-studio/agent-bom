"""Let background warm-ups finish, or stop, before the interpreter finalizes.

Warm-up workers run on daemon threads so they never hold a process open. On
Python 3.11-3.13 a daemon thread still running Python when the interpreter
finalizes is ended with ``pthread_exit`` at its next GIL acquire. Inside
pydantic-core's native frames that forced unwind aborts the process
(``FATAL: exception not rethrown``, SIGABRT) or crashes it (SIGSEGV), after
work it had already committed. Python 3.14 parks such threads instead.

At exit (``atexit``, which runs after non-daemon threads are joined and before
finalization) new warm-ups are refused, running ones stop at their next step,
and the exit waits for them at most ``EXIT_WAIT_SECONDS``.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time
from collections.abc import Callable

logger = logging.getLogger(__name__)

#: Bounded so a stuck warm-up never outlasts an orchestrator's termination grace period.
EXIT_WAIT_SECONDS = 10.0

_STOPPING = threading.Event()
_LOCK = threading.Lock()
_WAITS: dict[str, Callable[[float], bool]] = {}
_REGISTERED = False


def stopping() -> bool:
    """True once the process has begun its exit drain; warm-ups start nothing new."""
    return _STOPPING.is_set()


def register_exit_wait(name: str, wait_idle: Callable[[float], bool]) -> None:
    """Have the exit drain call ``wait_idle(seconds)`` for one background worker.

    Registered on first use, after the stores a warm-up reads are set up, so the
    drain runs before their own exit hooks close connection pools.
    """
    global _REGISTERED
    with _LOCK:
        _WAITS[name] = wait_idle
        if not _REGISTERED:
            atexit.register(drain_at_exit)
            _REGISTERED = True


def unregister_exit_wait(name: str) -> None:
    with _LOCK:
        _WAITS.pop(name, None)


def _finished(wait_idle: Callable[[float], bool], seconds: float) -> bool:
    try:
        return bool(wait_idle(seconds))
    except Exception:  # broad-except: one worker's failed wait must not stop the exit drain for the others
        return False


def drain_background_work(timeout: float) -> list[str]:
    """Refuse new warm-ups and wait for running ones; returns the workers still running."""
    _STOPPING.set()
    deadline = time.monotonic() + max(0.0, timeout)
    with _LOCK:
        waits = list(_WAITS.items())
    unfinished = [name for name, wait_idle in waits if not _finished(wait_idle, max(0.0, deadline - time.monotonic()))]
    if unfinished:
        logger.warning("Background work still running at exit after %.0f s: %s", timeout, ", ".join(unfinished))
    return unfinished


def drain_at_exit() -> None:
    drain_background_work(EXIT_WAIT_SECONDS)


def reset_background_exit() -> None:
    """Accept warm-ups again, as at import; for test isolation."""
    _STOPPING.clear()


__all__ = [
    "EXIT_WAIT_SECONDS",
    "drain_at_exit",
    "drain_background_work",
    "register_exit_wait",
    "reset_background_exit",
    "stopping",
    "unregister_exit_wait",
]
