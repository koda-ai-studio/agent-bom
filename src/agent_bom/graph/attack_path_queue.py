"""Ranked, filterable page of the attack-path queue, shared by REST and MCP.

The stores return persisted paths ordered by stored ``composite_risk``; this
module re-ranks a bounded window of them by on-path exploitability evidence
(see :mod:`agent_bom.graph.attack_path_queue_rank`) before slicing the page, so
pagination, totals, and filters all describe the same ordered set.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.attack_path_queue_rank import rank_attack_paths, ranking_node_ids
from agent_bom.graph.container import AttackPath
from agent_bom.graph.path_derivation import _derived_attack_paths

# Persisted paths re-ranked per request. A larger snapshot ranks its top window
# by stored score and reports ``ranking.complete = false``.
RANK_WINDOW = 20_000


def attack_path_rank_window() -> int:
    return RANK_WINDOW


@dataclass(slots=True)
class AttackPathFilters:
    min_severity: str | None = None
    has_credential: bool | None = None
    source_type: str | None = None

    def active(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in (
                ("min_severity", self.min_severity),
                ("has_credential", self.has_credential),
                ("source_type", self.source_type),
            )
            if value is not None
        }


@dataclass(slots=True)
class RankedPathPage:
    scan_id: str
    created_at: str
    paths: list[AttackPath]
    total: int
    snapshot_total: int
    ranking: dict[str, Any] = field(default_factory=dict)


def _rank_and_slice(
    candidates: list[AttackPath],
    nodes_by_id: dict[str, Any],
    *,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
) -> tuple[list[AttackPath], int]:
    ranked = rank_attack_paths(
        candidates,
        nodes_by_id,
        min_severity=filters.min_severity,
        has_credential=filters.has_credential,
        source_type=filters.source_type,
    )
    return ranked[offset : offset + limit], len(ranked)


def _ranking_meta(*, snapshot_total: int, window: int) -> dict[str, Any]:
    complete = snapshot_total <= window
    return {
        "method": "exploitability_evidence",
        "order": ["evidence_tier", "is_kev", "severity", "composite_risk", "credential_count", "source", "target"],
        "window": window,
        "complete": complete,
        "scope": "all_snapshot_paths" if complete else "top_window_by_stored_composite_risk",
    }


def ranked_persisted_path_page(
    graph_store: Any,
    *,
    scan_id: str,
    tenant_id: str,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
) -> RankedPathPage:
    window = attack_path_rank_window()
    effective_scan_id, created_at, candidates, snapshot_total = graph_store.attack_paths(
        scan_id=scan_id,
        tenant_id=tenant_id,
        offset=0,
        limit=window,
    )
    if snapshot_total == 0:
        return RankedPathPage(effective_scan_id, created_at, [], 0, 0)
    nodes = graph_store.nodes_by_ids(scan_id=effective_scan_id, tenant_id=tenant_id, node_ids=ranking_node_ids(candidates))
    nodes_by_id = {node.id: node for node in nodes}
    page, total = _rank_and_slice(candidates, nodes_by_id, offset=offset, limit=limit, filters=filters)
    return RankedPathPage(
        effective_scan_id,
        created_at,
        page,
        total,
        snapshot_total,
        _ranking_meta(snapshot_total=snapshot_total, window=window),
    )


def ranked_snapshot_path_page(
    graph_store: Any,
    *,
    scan_id: str,
    tenant_id: str,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
) -> RankedPathPage | None:
    """Read a queue page in the order fixed at persist; ``None`` without a current index."""
    reader = getattr(graph_store, "snapshot_queue_page", None)
    page = reader(tenant_id=tenant_id, scan_id=scan_id, offset=offset, limit=limit, **filters.active()) if reader is not None else None
    if page is None:
        return None
    ranking = _ranking_meta(snapshot_total=page.snapshot_total, window=page.snapshot_total or 1)
    return RankedPathPage(page.scan_id, page.created_at, page.paths, page.total, page.snapshot_total, ranking)


def ranked_derived_path_page(
    graph: Any,
    derived_paths: list[AttackPath],
    *,
    offset: int,
    limit: int,
    filters: AttackPathFilters | None = None,
) -> RankedPathPage:
    page, total = _rank_and_slice(derived_paths, graph.nodes, offset=offset, limit=limit, filters=filters or AttackPathFilters())
    return RankedPathPage(
        graph.scan_id,
        graph.created_at,
        page,
        total,
        len(derived_paths),
        _ranking_meta(snapshot_total=len(derived_paths), window=len(derived_paths) or 1),
    )


def _derived_attack_path_page(graph: Any, *, offset: int, limit: int, filters: AttackPathFilters | None = None) -> RankedPathPage:
    return ranked_derived_path_page(graph, _derived_attack_paths(graph), offset=offset, limit=limit, filters=filters)


@dataclass(slots=True)
class QueuePage:
    """A ranked queue page plus where its paths came from."""

    ranked: RankedPathPage
    materialized_paths: int
    derived_paths: int
    source: str
    derivation_truncated: bool = False

    @property
    def covers_all_matches(self) -> bool:
        """Every path matching the filters is ranked and present in ``ranked.paths``.

        A paged read never covers all matches; a whole-queue read covers them
        only when nothing was cut by the rank window, the node budget or a
        search cap.
        """
        ranking_complete = bool((self.ranked.ranking or {}).get("complete", True))
        return ranking_complete and not self.derivation_truncated and len(self.ranked.paths) >= self.ranked.total


_Call = Callable[..., Awaitable[Any]]


async def _to_thread(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(fn, *args, **kwargs)


async def ranked_queue_page(
    graph_store: Any,
    *,
    tenant_id: str,
    scan_id: str,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
    enrich: Callable[[Any, str], Any],
    store_call: _Call = _to_thread,
    compute_call: _Call = _to_thread,
    node_budget: int | None = None,
) -> QueuePage:
    """The attack-path queue page every surface ranks the same way.

    Order of evidence: the snapshot's current path index, else persisted path
    rows, else paths derived from the loaded topology. REST passes its
    admission-controlled executors; MCP uses plain worker threads. ``enrich``
    adds runtime evidence to a topology loaded for read-time derivation.
    """
    page_args = {"offset": offset, "limit": limit, "filters": filters}
    indexed = await store_call(ranked_snapshot_path_page, graph_store, scan_id=scan_id, tenant_id=tenant_id, **page_args)
    if indexed is not None:
        return QueuePage(indexed, 0, indexed.snapshot_total, "derived_graph_paths")
    ranked = await store_call(ranked_persisted_path_page, graph_store, scan_id=scan_id, tenant_id=tenant_id, **page_args)
    if ranked.snapshot_total:
        return QueuePage(ranked, ranked.snapshot_total, 0, "persisted_graph_paths")
    load_kwargs = {"node_budget": node_budget} if node_budget is not None else {}
    graph = await store_call(graph_store.load_graph, scan_id=ranked.scan_id or "", tenant_id=tenant_id, **load_kwargs)
    graph = await compute_call(enrich, graph, tenant_id)
    ranked = await compute_call(_derived_attack_path_page, graph, **page_args)
    return QueuePage(ranked, 0, ranked.snapshot_total, "derived_graph_paths", bool(graph.completeness.truncated))


__all__ = [
    "_derived_attack_path_page",
    "AttackPathFilters",
    "QueuePage",
    "RankedPathPage",
    "ranked_queue_page",
    "attack_path_rank_window",
    "ranked_derived_path_page",
    "ranked_persisted_path_page",
    "ranked_snapshot_path_page",
]
