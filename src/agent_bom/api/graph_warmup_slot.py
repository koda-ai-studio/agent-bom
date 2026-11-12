"""One slot for the post-commit warm-ups (roll-up views, reachability index, exec reads).

Each warm-up loads the tenant's whole graph or stored evidence, and a push
starts all of them at once. On their own threads they held two or three copies
of a 200-agent graph at the same time as the current-estate rebuild: about
2 GiB resident against the pilot's 2 GiB limit. Under the GIL running them
together bought almost no wall time, so they now take turns.

A holder may wait on a tenant's current-graph build gate, but no builder takes
this slot, so the order cannot cycle. Requests never take it.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

_SLOT = threading.Lock()


@contextmanager
def warmup_slot() -> Iterator[None]:
    """Run one tenant's warm-up while no other post-commit warm-up runs in this process."""
    with _SLOT:
        yield


__all__ = ["warmup_slot"]
