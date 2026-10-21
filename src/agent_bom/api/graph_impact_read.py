"""One read of a node's graph holders, shared by REST ``/v1/graph/impact`` and MCP.

``blast_radius`` and ``graph_reach`` answer "what holds or reaches this node"
from the same pinned snapshot, alias resolution and reverse walk as the REST
route, so the two surfaces cannot report different holders for one node.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from agent_bom.api.graph_generation import optional_generation
from agent_bom.graph.node_alias_resolution import resolve_snapshot_node_id
from agent_bom.graph.reach_view import reach_interpretation

DEFAULT_IMPACT_DEPTH = 4
MAX_IMPACT_DEPTH = 10

#: Graph read failures a caller may degrade on instead of failing its answer.
GRAPH_READ_ERRORS = (NotImplementedError, AttributeError, LookupError, OSError, RuntimeError, ValueError, HTTPException)


def read_node_impact(
    store: Any,
    *,
    tenant_id: str,
    scan_id: str | None,
    node_id: str,
    max_depth: int | None = None,
    snapshot_generation: str | None = None,
    direction: str = "reverse",
) -> dict[str, Any] | None:
    """The node's impact walk (reverse: upstream holders; forward: what it reaches) on the pinned snapshot, or ``None``."""
    identity = optional_generation(store, tenant=tenant_id, scan_id=scan_id or "", generation=snapshot_generation, offset=0)
    effective_scan_id = identity[0] if identity else scan_id or ""
    read_id, resolved_from = resolve_snapshot_node_id(store, tenant_id=tenant_id, scan_id=effective_scan_id, node_id=node_id)
    max_depth, depth_basis = _impact_depth(store, tenant_id, effective_scan_id, read_id, max_depth, direction)
    impact = store.impact_of(scan_id=effective_scan_id, tenant_id=tenant_id, node_id=read_id, max_depth=max_depth, direction=direction)
    if impact is None:
        return None
    return {
        **impact,
        "scan_id": effective_scan_id,
        "tenant_id": tenant_id,
        "snapshot_generation": identity[1] if identity else None,
        "direction": direction,
        "max_depth": max_depth,
        "depth_basis": depth_basis,
        "interpretation": reach_interpretation(max_depth=max_depth, direction="in" if direction == "reverse" else "out"),
        "resolved_from": resolved_from,
        "_identity": identity,
    }


def _impact_depth(store: Any, tenant_id: str, scan_id: str, node_id: str, requested: int | None, direction: str) -> tuple[int, str]:
    """A requested depth wins; otherwise walk at least as far as the longest materialized path ending here.

    A fixed default shorter than a stored agent-to-finding path reported fewer
    holders than the attack-path queue shows for the same node.
    """
    if requested is not None:
        return requested, "requested"
    if direction != "reverse":
        return DEFAULT_IMPACT_DEPTH, "default"
    reader = getattr(store, "longest_path_to", None)
    try:
        longest = int(reader(tenant_id=tenant_id, scan_id=scan_id, node_id=node_id)) if callable(reader) else 0
    except GRAPH_READ_ERRORS:
        longest = 0
    if longest > DEFAULT_IMPACT_DEPTH:
        return min(longest, MAX_IMPACT_DEPTH), "longest_materialized_path"
    return DEFAULT_IMPACT_DEPTH, "default"


def impact_holders_by_type(store: Any, impact: dict[str, Any]) -> dict[str, list[str]]:
    """The walk's holder ids grouped by entity type, in walk order."""
    affected = [str(node) for node in impact.get("affected_nodes") or []]
    kinds = {
        node.id: str(getattr(node.entity_type, "value", node.entity_type))
        for node in store.nodes_by_ids(tenant_id=impact["tenant_id"], scan_id=impact["scan_id"], node_ids=set(affected))
    }
    grouped: dict[str, list[str]] = {}
    for node_id in affected:
        grouped.setdefault(kinds.get(node_id, "unknown"), []).append(node_id)
    return grouped
