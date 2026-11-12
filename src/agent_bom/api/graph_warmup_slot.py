"""One slot for the post-commit warm-ups (roll-up views, reachability index, exec reads).

Each warm-up loads the tenant's whole graph or stored evidence, and a push
starts all of them at once. On their own threads they held two or three copies
of a 200-agent graph at the same time as the current-estate rebuild: about
2 GiB resident against the pilot's 2 GiB limit. Under the GIL running them
together bought almost no wall time, so they now take turns.

A holder may wait on a tenant's current-graph build gate, but no builder takes
this slot, so the order cannot cycle. Requests never take it.

Once it holds the slot, a warm-up first lets the process's current-graph
builds finish (at most ``BUILD_YIELD_SECONDS``): the rebuild a push or a read
asked for is what readers wait on, and a warm-up loading its own graph copy
beside it doubled resident memory and slowed both on a limited CPU.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from agent_bom.api.current_graph_builds import wait_for_current_builds

_SLOT = threading.Lock()
BUILD_YIELD_SECONDS = 120.0


@contextmanager
def warmup_slot() -> Iterator[None]:
    """Run one tenant's warm-up while no other post-commit warm-up runs in this process."""
    with _SLOT:
        wait_for_current_builds(BUILD_YIELD_SECONDS)
        yield


__all__ = ["warmup_slot"]
