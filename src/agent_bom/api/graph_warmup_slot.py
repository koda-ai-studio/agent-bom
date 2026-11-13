"""One slot for the post-commit warm-ups (roll-up views, reachability index, exec reads).

Each warm-up loads the tenant's whole graph or stored evidence, and a push
starts all of them at once. On their own threads they held two or three copies
of a 200-agent graph at the same time as the current-estate rebuild: about
2 GiB resident against the pilot's 2 GiB limit. Under the GIL running them
together bought almost no wall time, so they now take turns.

A holder may wait on a tenant's current-graph build gate, but no builder takes
this slot, so the order cannot cycle. Requests never take it.

Once it holds the slot, a warm-up first lets foreground graph work finish: an
ingest that still holds the graph it just wrote (commit hooks schedule the
warm-ups from inside it), then the process's current-graph builds, which is
what readers wait on. Both waits share ``BUILD_YIELD_SECONDS``. Foreground
work never takes this slot either, so waiting on it cannot deadlock.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from agent_bom.api.current_graph_builds import wait_for_current_builds
from agent_bom.core.background_yield import background_work

_SLOT = threading.Lock()
BUILD_YIELD_SECONDS = 120.0
_FOREGROUND = threading.Condition()
_foreground_count = 0


@contextmanager
def foreground_graph_work() -> Iterator[None]:
    """Mark graph work readers wait on (an ingest's persist and commit); warm-ups yield to it."""
    global _foreground_count  # noqa: PLW0603
    with _FOREGROUND:
        _foreground_count += 1
    try:
        yield
    finally:
        with _FOREGROUND:
            _foreground_count -= 1
            _FOREGROUND.notify_all()


def foreground_active() -> bool:
    with _FOREGROUND:
        return _foreground_count > 0


def _wait_for_foreground(deadline: float) -> None:
    with _FOREGROUND:
        while _foreground_count and (remaining := deadline - time.monotonic()) > 0:
            _FOREGROUND.wait(remaining)


@contextmanager
def warmup_slot() -> Iterator[None]:
    """Run one tenant's warm-up while no other post-commit warm-up runs in this process."""
    with _SLOT:
        deadline = time.monotonic() + BUILD_YIELD_SECONDS
        _wait_for_foreground(deadline)
        wait_for_current_builds(max(0.0, deadline - time.monotonic()))
        # Warm-ups step aside at their yield points while requests are in flight.
        with background_work():
            yield


__all__ = ["foreground_active", "foreground_graph_work", "warmup_slot"]
