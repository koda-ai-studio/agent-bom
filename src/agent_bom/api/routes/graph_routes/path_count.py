"""The attack-path total ``/v1/graph`` stats share with ``/v1/graph/attack-paths``.

Snapshot stats count persisted ``attack_paths`` rows, which topology-only
snapshots never write, while the queue reads its path index or derives paths
on read. The node page reports the queue's own total instead, cached per
tenant, scan and snapshot generation: a new generation is a new key, so
rotation never serves a stale count and no worker has to invalidate another's
cache.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any

from agent_bom.api.graph_generation import snapshot_fingerprint
from agent_bom.api.routes.graph_routes import _runtime

_CacheKey = tuple[str, str, str, str]
_Entry = tuple[int, float, bool]

_CACHE: OrderedDict[_CacheKey, _Entry] = OrderedDict()
_LOCK = threading.Lock()
_CACHE_MAX = 256


def clear() -> None:
    with _LOCK:
        _CACHE.clear()


def _cached(key: _CacheKey) -> _Entry | None:
    with _LOCK:
        hit = _CACHE.get(key)
        if hit is not None:
            _CACHE.move_to_end(key)
        return hit


def _remember(key: _CacheKey, value: _Entry) -> None:
    with _LOCK:
        _CACHE[key] = value
        _CACHE.move_to_end(key)
        while len(_CACHE) > _CACHE_MAX:
            _CACHE.popitem(last=False)


async def _count_snapshot_paths(graph_store: Any, *, tenant: str, scan_id: str) -> _Entry | None:
    """``(total, max composite risk, complete)`` from the snapshot's queue index; ``None`` without one."""
    reader = getattr(graph_store, "snapshot_path_summary", None)
    if not callable(reader):
        return None
    summary = await _runtime._graph_store_call(reader, tenant_id=tenant, scan_id=scan_id)
    return None if summary is None else (int(summary[0]), float(summary[1]), True)


def remember_queue_total(tenant: str, generation: str, ranked: Any, stats: dict[str, Any], *, filtered: bool) -> None:
    """Record the unfiltered queue total a derive-on-read snapshot served, for the node page to report."""
    if generation and not filtered:
        complete = bool((ranked.ranking or {}).get("complete", True))
        entry = (int(ranked.snapshot_total), float(stats.get("max_attack_path_risk") or 0.0), complete)
        _remember((tenant, ranked.scan_id, generation, "derived"), entry)


async def with_queue_path_count(
    stats: dict[str, Any],
    graph_store: Any,
    *,
    tenant: str,
    scan_id: str,
    generation: str | None,
) -> dict[str, Any]:
    """``stats`` with ``attack_path_count`` / ``max_attack_path_risk`` equal to the queue's.

    Never loads the graph: the count comes from the queue index, else from the
    total the queue route derived for this generation. A snapshot with neither
    keeps its persisted count and says so in ``attack_path_count_basis``.
    """
    indexed = (tenant, scan_id, generation, "index") if generation else None
    entry = _cached(indexed) if indexed else None
    if entry is None:
        entry = await _count_snapshot_paths(graph_store, tenant=tenant, scan_id=scan_id)
        if entry is not None and indexed:
            _remember(indexed, entry)
    if entry is None and generation:
        entry = _cached((tenant, scan_id, generation, "derived"))
    if entry is None:
        return {**stats, "attack_path_count_basis": "persisted_paths"}
    total, max_risk, complete = entry
    stats = {**stats, "attack_path_count_basis": "queue_total"}
    stored = int(stats.get("attack_path_count") or 0)
    if total and stored == 0:
        return {**stats, "attack_path_count": total, "max_attack_path_risk": max_risk}
    if complete and total != stored:
        return {**stats, "attack_path_count": total}
    return stats


async def node_page_stats(
    graph_store: Any,
    scan_id: str,
    tenant: str,
    entity_types: set[str] | None,
    min_severity_rank: int,
    identity: tuple[str, str] | None,
) -> dict[str, Any]:
    """Snapshot stats for one node page, with the queue's attack-path total.

    A backend that cannot pin a generation is keyed by its snapshot receipt.
    """
    stats = await _runtime._graph_store_call(
        graph_store.snapshot_stats,
        scan_id=scan_id,
        tenant_id=tenant,
        entity_types=entity_types,
        min_severity_rank=min_severity_rank,
    )
    count_identity = identity or await _runtime._graph_store_call(snapshot_fingerprint, graph_store, tenant=tenant, scan_id=scan_id)
    generation = count_identity[1] if count_identity else None
    return await with_queue_path_count(stats, graph_store, tenant=tenant, scan_id=scan_id, generation=generation)


__all__ = ["clear", "node_page_stats", "remember_queue_total", "with_queue_path_count"]
