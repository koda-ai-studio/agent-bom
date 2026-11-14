"""Let background Python loops step aside while requests are in flight.

Under the GIL a CPU-bound thread beside a request makes the request wait for
the interpreter every time it returns from I/O: a 95 ms graph read took 9.4 s
beside a busy loop. Background work marks its thread with
``background_work()`` and iterates through ``yielding()``; at each yield point,
while any request is in flight, it sleeps (holding no GIL) for at most
``MAX_PAUSE_SECONDS``. The bound means constant traffic slows background work
but cannot stop it. Request threads are never marked, so they never pause.

Whether a request is in flight is registered by the API layer, so this module
has no dependencies. The clock is bound at import, so a test that patches the
``time`` module cannot be consumed by a background thread.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from time import monotonic as _monotonic
from time import sleep as _sleep
from typing import TypeVar

T = TypeVar("T")

MAX_PAUSE_SECONDS = 0.1
_POLL_SECONDS = 0.005
_state = threading.local()
_requests_in_flight: Callable[[], bool] = lambda: False  # noqa: E731


def register_request_probe(probe: Callable[[], bool]) -> None:
    """Install the check for requests in flight (the API layer does this at import)."""
    global _requests_in_flight
    _requests_in_flight = probe


def in_background() -> bool:
    return bool(getattr(_state, "depth", 0))


@contextmanager
def background_work() -> Iterator[None]:
    """Mark this thread's work as deferrable for the duration."""
    _state.depth = getattr(_state, "depth", 0) + 1
    try:
        yield
    finally:
        _state.depth -= 1


def pause_for_requests() -> None:
    """On a background thread, wait while requests are in flight, at most ``MAX_PAUSE_SECONDS``."""
    if not in_background():
        return
    deadline = _monotonic() + MAX_PAUSE_SECONDS
    while _requests_in_flight() and _monotonic() < deadline:
        _sleep(_POLL_SECONDS)


def yielding(rows: Iterable[T], *, every: int = 512) -> Iterator[T]:
    """Yield ``rows``, pausing for requests every ``every`` items on a background thread."""
    for index, row in enumerate(rows, 1):
        yield row
        if index % every == 0:
            pause_for_requests()


__all__ = ["MAX_PAUSE_SECONDS", "background_work", "in_background", "pause_for_requests", "register_request_probe", "yielding"]
