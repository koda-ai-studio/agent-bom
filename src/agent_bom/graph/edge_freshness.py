"""Edge freshness receipts for the snapshot that collected each relationship.

Hop receipts only complete when an edge carries ``freshness`` evidence. This
stamps it from the edge's own observation time relative to the snapshot:

* ``fresh`` - observed no earlier than ``GRAPH_EDGE_FRESHNESS_HOURS`` before the
  snapshot was created. An observation at or after creation was collected by
  this snapshot's build.
* ``stale`` - observed before that window, e.g. evidence carried forward from
  an older collection.
* absent - no parseable observation time, so there is no basis either way.

Freshness already recorded on the edge (or by correlation provenance) is never
replaced; correlation recomputes its own at decision time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom import config
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge

FRESH = "fresh"
STALE = "stale"
_OBSERVATION_KEYS = ("observed_at", "collected_at")
_STORE_WRITE_BATCH = 500


def _parse(value: object, cache: dict[str, datetime | None]) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if value in cache:
        return cache[value]
    try:
        parsed: datetime | None = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is not None:
        parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    cache[value] = parsed
    return parsed


def _recorded(edge: UnifiedEdge) -> bool:
    correlation = edge.provenance.get("correlation") if isinstance(edge.provenance, dict) else None
    return bool(edge.evidence.get("freshness")) or (isinstance(correlation, dict) and bool(correlation.get("freshness")))


def _observed_at(edge: UnifiedEdge, cache: dict[str, datetime | None]) -> datetime | None:
    """An explicit collector timestamp wins over the edge's ``last_seen``."""
    for source in (edge.evidence, edge.provenance if isinstance(edge.provenance, dict) else {}):
        for key in _OBSERVATION_KEYS:
            parsed = _parse(source.get(key), cache)
            if parsed is not None:
                return parsed
    return _parse(edge.last_seen, cache)


def edge_freshness(
    edge: UnifiedEdge,
    reference: datetime,
    window: timedelta,
    cache: dict[str, datetime | None] | None = None,
) -> str | None:
    observed = _observed_at(edge, cache if cache is not None else {})
    if observed is None:
        return None
    return FRESH if observed >= reference - window else STALE


def stamp_edge_freshness(graph: UnifiedGraph, *, window_hours: int | None = None) -> dict[str, int]:
    """Stamp ``evidence["freshness"]`` on every unstamped edge; return the tally.

    Idempotent: a second pass only counts what the first recorded.
    """
    counts = {FRESH: 0, STALE: 0, "unknown": 0, "recorded": 0}
    cache: dict[str, datetime | None] = {}
    reference = _parse(graph.created_at, cache)
    hours = config.GRAPH_EDGE_FRESHNESS_HOURS if window_hours is None else window_hours
    window = timedelta(hours=max(0, int(hours)))
    store_backed = _is_store_backed(graph)
    pending: list[UnifiedEdge] = []
    for edge in graph.edges:
        if _recorded(edge):
            counts["recorded"] += 1
            continue
        verdict = edge_freshness(edge, reference, window, cache) if reference is not None else None
        if verdict is None:
            counts["unknown"] += 1
            continue
        counts[verdict] += 1
        edge.evidence["freshness"] = verdict
        if store_backed:
            pending.append(edge)
            if len(pending) >= _STORE_WRITE_BATCH:
                _write_back(graph, pending)
    if pending:
        _write_back(graph, pending)
    return counts


def _is_store_backed(graph: Any) -> bool:
    from agent_bom.graph.store_backed import StoreBackedUnifiedGraph

    return isinstance(graph, StoreBackedUnifiedGraph)


def _write_back(graph: Any, edges: list[UnifiedEdge]) -> None:
    # Store-backed edge views yield copies. Write them as-is: re-adding through
    # add_edge would run the evidence merge and derive unrelated keys.
    graph.write_edges(edges)
    edges.clear()


__all__ = ["FRESH", "STALE", "edge_freshness", "stamp_edge_freshness"]
