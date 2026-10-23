"""KEV slice of the attack-path queue, with the semantics MCP ``exposure_paths kev`` uses.

The stored queue index has no KEV facet, so the slice reads the whole ranked
queue for the other filters (bounded by ``SEARCH_PATH_CAP``), keeps the paths
whose finding hops are (or are not) known-exploited, and pages that. When the
whole-queue read was cut short the ranking is reported incomplete, so the
total is a lower bound rather than a confident count.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.graph.attack_path_queue import AttackPathFilters
from agent_bom.graph.attack_path_queue_rank import path_is_kev
from agent_bom.mcp_tools.exposure_queue import whole_queue


async def kev_queue_page(
    graph_store: Any, tenant: str, scan_id: str, *, kev: bool, offset: int, limit: int, filters: AttackPathFilters
) -> tuple[Any, int, int, str, list[Any]]:
    """``(ranked page, materialized, derived, source, every matching path)``."""
    whole = await whole_queue(graph_store, tenant, scan_id, filters)
    candidates = whole.ranked.paths
    hop_ids = {hop for path in candidates for hop in path.hops}
    nodes = await _runtime._graph_store_call(graph_store.nodes_by_ids, scan_id=whole.ranked.scan_id, tenant_id=tenant, node_ids=hop_ids)
    by_id = {node.id: node for node in nodes}
    matched = [path for path in candidates if path_is_kev(path, by_id) == kev]
    ranking = {**(whole.ranked.ranking or {})}
    ranking["complete"] = bool(ranking.get("complete", True)) and whole.covers_all_matches
    ranked = replace(whole.ranked, paths=matched[offset : offset + limit], total=len(matched), ranking=ranking)
    return ranked, whole.materialized_paths, whole.derived_paths, whole.source, matched
