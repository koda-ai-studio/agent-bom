"""Attack-path queue focused on one node or finding occurrence.

A finding deep link must land on its own path wherever it ranks; filtering a
loaded page client-side cannot find a path ranked outside that page. This reads
the whole ranked queue (the same bounded read the MCP exposure tools use) and
keeps queue order, so the focused page is a filtered slice of the global queue.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from fastapi import Query

from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.graph.attack_path_queue import AttackPathFilters, RankedPathPage
from agent_bom.mcp_tools.exposure_queue import PathQuery, whole_queue


class PathFocusQuery:
    """Optional ``node_id`` / ``finding_id`` focus parameters of the attack-path queue."""

    def __init__(
        self,
        node_id: str | None = Query(
            None, max_length=512, pattern=r"^[^\x00]*$", description="Only paths through this node (replaced ids resolve to canonical)"
        ),
        finding_id: str | None = Query(
            None, max_length=512, pattern=r"^[^\x00]*$", description="Only paths carrying this finding occurrence"
        ),
    ) -> None:
        self.node_id = node_id or None
        self.finding_id = finding_id or None

    def active(self) -> dict[str, str]:
        return {key: value for key, value in (("node_id", self.node_id), ("finding_id", self.finding_id)) if value}


async def focused_queue_page(
    graph_store: Any,
    tenant: str,
    scan_id: str,
    *,
    node_id: str | None,
    finding_id: str | None,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
) -> tuple[RankedPathPage, int, int, str, dict[str, Any]]:
    read_id, resolved_from = await _runtime.resolve_node_id(graph_store, tenant, scan_id, node_id) if node_id else (None, None)
    query = PathQuery(node_id=read_id or None, finding_id=finding_id or None)
    page = await whole_queue(graph_store, tenant, scan_id, filters)
    matched = [path for path in page.ranked.paths if query.matches(path, {})]
    focus = {
        "node_id": read_id or None,
        "finding_id": finding_id or None,
        "resolved_from": resolved_from,
        # False when the rank window, node budget or search cap cut the read: a miss is then not proof of absence.
        "covers_all_matches": page.covers_all_matches,
    }
    ranked = replace(page.ranked, paths=matched[offset : offset + limit], total=len(matched))
    return ranked, page.materialized_paths, page.derived_paths, page.source, focus
