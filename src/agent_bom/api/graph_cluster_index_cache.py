"""One grouped-map index per snapshot generation, built once and shared by every read.

The index (:class:`agent_bom.graph.cluster_index.ClusterIndex`) is the
per-snapshot aggregation behind ``GET /v1/graph/cluster-map``: building it
reads the snapshot once through the store's lean ``load_cluster_rows``
projection; every later read of the same generation, including expansions,
paging and focus, is answered from it in milliseconds.

Keys carry the tenant and the snapshot's generation (or its receipt
fingerprint), so a replaced snapshot or another tenant can never be answered
from an entry. Concurrent first reads of one generation in this process build
it once (single flight). The cache is per process, like the roll-up cache: an
API worker process that has not seen a generation builds its own. Bounded to a
few generations so memory stays flat.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any

from agent_bom.graph.cluster_index import ClusterIndex

#: Generations retained per process; the latest snapshot of a couple of tenants.
MAX_ENTRIES = 4

_LOCK = threading.Lock()
_ENTRIES: OrderedDict[tuple[Any, ...], ClusterIndex] = OrderedDict()
_BUILDING: dict[tuple[Any, ...], threading.Event] = {}
_STATS = {"builds": 0, "hits": 0}


def build_cluster_index(store: Any, *, tenant_id: str, scan_id: str) -> ClusterIndex:
    """Read one snapshot's lean projection and index it (the cold path)."""
    loader = getattr(store, "load_cluster_rows", None)
    if callable(loader):
        return ClusterIndex.from_rows(*loader(tenant_id=tenant_id, scan_id=scan_id))
    # A backend without the lean read (the experimental Neptune store) loads the topology projection.
    from agent_bom.api.graph_rollup_prewarm import load_rollup_source

    return ClusterIndex.from_graph(load_rollup_source(store, tenant_id=tenant_id, scan_id=scan_id, node=None, mode="rollup"))


def cache_key(store: Any, tenant_id: str, identity: tuple[str, str]) -> tuple[Any, ...]:
    # The route's store may be a per-request current-estate wrapper; key on its stable backing store.
    return (id(getattr(store, "_graph_store", store)), tenant_id, tuple(identity))


def cluster_index(store: Any, *, tenant_id: str, scan_id: str, identity: tuple[str, str] | None) -> ClusterIndex:
    """The index for one snapshot generation; built at most once per process while retained."""
    if identity is None or not identity[1]:
        # Without a generation an entry could outlive its snapshot: build, never cache.
        return build_cluster_index(store, tenant_id=tenant_id, scan_id=scan_id)
    key = cache_key(store, tenant_id, identity)
    while True:
        with _LOCK:
            hit = _ENTRIES.get(key)
            if hit is not None:
                _ENTRIES.move_to_end(key)
                _STATS["hits"] += 1
                return hit
            waiting = _BUILDING.get(key)
            if waiting is None:
                done = _BUILDING[key] = threading.Event()
                break
        waiting.wait()
    try:
        index = build_cluster_index(store, tenant_id=tenant_id, scan_id=identity[0] or scan_id)
        with _LOCK:
            _STATS["builds"] += 1
            _ENTRIES[key] = index
            while len(_ENTRIES) > MAX_ENTRIES:
                _ENTRIES.popitem(last=False)
        return index
    finally:
        with _LOCK:
            _BUILDING.pop(key, None)
        done.set()


def stats() -> dict[str, int]:
    with _LOCK:
        return {**_STATS, "entries": len(_ENTRIES)}


def clear() -> None:
    with _LOCK:
        _ENTRIES.clear()
        _STATS.update(builds=0, hits=0)


__all__ = ["MAX_ENTRIES", "build_cluster_index", "cache_key", "clear", "cluster_index", "stats"]
