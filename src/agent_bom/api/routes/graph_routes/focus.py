"""Attack-path queue focused on one node or finding occurrence.

A finding deep link must land on its own path wherever it ranks; filtering a
loaded page client-side cannot find a path ranked outside that page. This reads
the whole ranked queue (the same bounded read the MCP exposure tools use) and
keeps queue order, so the focused page is a filtered slice of the global queue.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from fastapi import HTTPException, Query

from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes.control_focus import ControlOccurrences
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
        advisory_id: str | None = Query(
            None,
            max_length=128,
            pattern=r"^[^\x00]*$",
            description=(
                "Only paths carrying this advisory. With finding_id it qualifies the occurrence instead: when paths record "
                "the advisory rather than the occurrence id, the occurrence resolves to paths through its node_id carrying it"
            ),
        ),
        framework: str | None = Query(None, max_length=64, pattern=r"^[A-Za-z0-9_.-]*$", description="Compliance framework of ``control``"),
        control: str | None = Query(
            None,
            max_length=64,
            pattern=r"^[^\x00]*$",
            description="Only paths carrying the current finding occurrences mapped to this framework control",
        ),
    ) -> None:
        self.node_id = node_id or None
        self.finding_id = finding_id or None
        self.advisory_id = advisory_id or None
        self.framework = framework or None
        self.control = control or None
        if bool(self.framework) != bool(self.control):
            raise HTTPException(400, "framework and control must be sent together.")

    def active(self) -> dict[str, str]:
        pairs = (
            ("node_id", self.node_id),
            ("finding_id", self.finding_id),
            ("advisory_id", self.advisory_id),
            ("framework", self.framework),
            ("control", self.control),
        )
        return {key: value for key, value in pairs if value}


def _carries_advisory(path: Any, advisory_id: str) -> bool:
    wanted = advisory_id.lower()
    values = [*path.vuln_ids, *path.finding_ids, *(hop for hop in path.hops if hop.startswith(("vuln:", "misconfig:")))]
    return any(wanted == str(value).lower() or str(value).lower().endswith(":" + wanted) for value in values)


async def focused_queue_page(
    graph_store: Any,
    tenant: str,
    scan_id: str,
    *,
    node_id: str | None,
    finding_id: str | None,
    advisory_id: str | None = None,
    control: tuple[str, str, ControlOccurrences] | None = None,
    offset: int,
    limit: int,
    filters: AttackPathFilters,
) -> tuple[RankedPathPage, int, int, str, dict[str, Any]]:
    read_id, resolved_from = await _runtime.resolve_node_id(graph_store, tenant, scan_id, node_id) if node_id else (None, None)
    query = PathQuery(node_id=read_id or None, finding_id=finding_id or None)
    page = await whole_queue(graph_store, tenant, scan_id, filters)
    matched = [path for path in page.ranked.paths if query.matches(path, {})]
    matched_by = "occurrence"
    if advisory_id and not finding_id:
        matched = [path for path in matched if _carries_advisory(path, advisory_id)]
        matched_by = "advisory"
    elif not matched and finding_id and advisory_id and read_id:
        # The finding store keys occurrences by id while paths record the advisory: the same
        # advisory on the occurrence's own node is that occurrence, never another asset's.
        node_only = PathQuery(node_id=read_id)
        matched = [path for path in page.ranked.paths if node_only.matches(path, {}) and _carries_advisory(path, advisory_id)]
        matched_by = "node_advisory"
    complete = page.covers_all_matches
    if control:
        matched = [path for path in matched if control[2].matches(path)]
        complete = complete and control[2].complete
    focus: dict[str, Any] = {
        "node_id": read_id or None,
        "finding_id": finding_id or None,
        "resolved_from": resolved_from,
        # False when the rank window, node budget or search cap cut the read: a miss is then not proof of absence.
        "covers_all_matches": complete,
    }
    if control:
        focus |= {"framework": control[0], "control": control[1], "control_findings": control[2].count}
    if advisory_id:
        focus |= {"advisory_id": advisory_id, "matched_by": matched_by}
    ranked = replace(page.ranked, paths=matched[offset : offset + limit], total=len(matched))
    return ranked, page.materialized_paths, page.derived_paths, page.source, focus
