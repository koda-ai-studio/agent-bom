"""``blast_radius`` holders and verdicts from the same reads REST serves.

Holders come from the ``/v1/graph/impact`` walk (:mod:`agent_bom.api.graph_impact_read`)
and each row's ``reachability`` from the findings projection, so MCP and the
dashboard never disagree about who holds an advisory or how reachable it is.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_bom.api.finding_reachability import project_attack_path_reachability
from agent_bom.api.graph_impact_read import GRAPH_READ_ERRORS, impact_holders_by_type, read_node_impact

_PUBLIC_HOLDER_KEYS = (
    "node_id",
    "resolved_from",
    "scan_id",
    "snapshot_generation",
    "affected_count",
    "affected_by_type",
    "affected_nodes",
    "completeness",
    "interpretation",
)


def blast_holders(store_factory: Callable[[], Any], *, tenant_id: str, scan_id: str | None, cve_id: str) -> dict[str, Any] | None:
    """The advisory node's REST impact walk plus its holders by type; ``None`` when unavailable."""
    try:
        store = store_factory()
        impact = read_node_impact(store, tenant_id=tenant_id, scan_id=scan_id, node_id=f"vuln:{cve_id}", max_depth=4)
        if impact is None:
            return None
        impact.pop("_identity", None)
        impact["holders_by_type"] = impact_holders_by_type(store, impact)
        return impact
    except GRAPH_READ_ERRORS:
        return None


def stamp_rows(rows: list[dict[str, Any]], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Stamp rows with the findings route's path rule and verdict over the snapshot's served paths."""
    stamped = [dict(row) for row in rows]
    project_attack_path_reachability(stamped, snapshot.get("paths") or [] if snapshot.get("available") else [])
    return stamped


def apply_holders(results: list[dict[str, Any]], holders: dict[str, Any] | None) -> None:
    """Replace per-row server/agent lists with the graph holders when the walk answered."""
    if holders is None:
        return
    by_type = holders["holders_by_type"]
    for result in results:
        result["affected_servers"] = list(by_type.get("server", []))
        result["affected_agents"] = list(by_type.get("agent", []))


def public_holders(holders: dict[str, Any] | None) -> dict[str, Any]:
    if holders is None:
        return {"source": "graph_impact", "status": "unavailable"}
    return {"source": "graph_impact", "status": "evaluated", **{key: holders.get(key) for key in _PUBLIC_HOLDER_KEYS}}
