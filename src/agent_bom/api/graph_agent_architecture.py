"""Tenant-scoped store reads behind ``/v1/graph/agent-architecture`` and the ``agent_architecture`` MCP tool.

Every read names the caller's tenant and the pinned snapshot. Framework-agent
nodes are paged from the store up to a bound; past it the answer says it is
incomplete instead of guessing. Harnesses are then paged in a stable order.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph import harness_view as view

# Agent nodes read per page, and the most framework agents one answer places.
AGENT_PAGE = 1_000
FRAMEWORK_AGENT_CAP = 5_000
MAX_AGENT_NODES_SCANNED = 50_000
MAX_STRUCTURAL_EDGES = 50_000
MAX_OVERLAY_EDGES = 20_000
MAX_FINDING_NODES = 5_000


def _framework_agents(store: Any, *, tenant_id: str, scan_id: str) -> tuple[list[Any], bool]:
    """Framework-agent nodes of the snapshot and whether every agent node was read."""
    found: list[Any] = []
    cursor: str | None = None
    scanned = 0
    while True:
        _, _, nodes, _, next_cursor = store.page_nodes(
            tenant_id=tenant_id, scan_id=scan_id, entity_types={"agent"}, cursor=cursor, limit=AGENT_PAGE
        )
        scanned += len(nodes)
        found.extend(node for node in nodes if node.attributes.get("agent_type") == view.FRAMEWORK_AGENT)
        if len(found) > FRAMEWORK_AGENT_CAP:
            return found[:FRAMEWORK_AGENT_CAP], False
        if not next_cursor or not nodes:
            return found, True
        if scanned >= MAX_AGENT_NODES_SCANNED:
            return found, False
        cursor = next_cursor


def _structural_edges(store: Any, *, tenant_id: str, scan_id: str, agent_ids: set[str]) -> tuple[list[Any], bool]:
    if not agent_ids:
        return [], True
    edges = store.edges_for_node_ids(
        tenant_id=tenant_id,
        scan_id=scan_id,
        node_ids=agent_ids,
        induced_only=True,
        relationships=set(view.STRUCTURAL_RELATIONSHIPS),
        limit=MAX_STRUCTURAL_EDGES + 1,
    )
    return list(edges[:MAX_STRUCTURAL_EDGES]), len(edges) <= MAX_STRUCTURAL_EDGES


def _overlay(
    store: Any,
    *,
    tenant_id: str,
    scan_id: str,
    harnesses: list[dict[str, Any]],
    members: dict[str, list[str]],
    nodes_by_id: dict[str, Any],
) -> bool:
    """Attach the security overlay; ``False`` when a bounded read may have left records out.

    Reads cover every member of each harness, not only the agents listed, so
    the harness rollup counts findings on agents past the listing cap.
    """
    agent_ids = {agent_id for harness in harnesses for agent_id in members[harness["harness_id"]]}
    roots = {harness["harness_id"] for harness in harnesses}
    outgoing = (
        store.edges_for_node_ids(tenant_id=tenant_id, scan_id=scan_id, node_ids=agent_ids, direction="out", limit=MAX_OVERLAY_EDGES)
        if agent_ids
        else []
    )
    incoming = (
        store.edges_for_node_ids(
            tenant_id=tenant_id, scan_id=scan_id, node_ids=roots, direction="in", relationships={"contains"}, limit=len(roots) * 4
        )
        if roots
        else []
    )
    reach, findings, declared_in = view.overlay_inputs([*outgoing, *incoming])
    all_findings = sorted({fid for ids in findings.values() for fid in ids})
    finding_ids = all_findings[:MAX_FINDING_NODES]
    lookup_ids = set(finding_ids) | {pid for pid in declared_in.values() if pid not in nodes_by_id}
    looked_up = (
        {node.id: node for node in store.nodes_by_ids(tenant_id=tenant_id, scan_id=scan_id, node_ids=lookup_ids)} if lookup_ids else {}
    )
    everything = {**looked_up, **nodes_by_id}
    for harness in harnesses:
        view.apply_overlay(harness, everything, reach, findings, declared_in, looked_up, members[harness["harness_id"]])
    return len(outgoing) < MAX_OVERLAY_EDGES and len(all_findings) <= MAX_FINDING_NODES


def _bound_reasons(*, agents: bool, edges: bool, overlay: bool) -> list[str]:
    """One reason per bounded read that may have left records out of this answer."""
    reasons = []
    if not agents:
        reasons.append(
            f"The agent read stopped at its bound ({FRAMEWORK_AGENT_CAP} framework agents or "
            f"{MAX_AGENT_NODES_SCANNED} agent nodes); framework agents past it are not placed."
        )
    if not edges:
        reasons.append(f"Only the first {MAX_STRUCTURAL_EDGES} delegation and shared-server edges were read.")
    if not overlay:
        reasons.append("The security overlay read hit its bound; some reach or finding records may be missing.")
    return reasons


def read_agent_architecture(store: Any, *, tenant_id: str, scan_id: str, offset: int, limit: int) -> dict[str, Any]:
    """One page of harnesses for ``tenant_id``'s snapshot ``scan_id`` (already resolved and pinned)."""
    agents, agents_complete = _framework_agents(store, tenant_id=tenant_id, scan_id=scan_id)
    nodes_by_id = {node.id: node for node in agents}
    raw_edges, edges_complete = _structural_edges(store, tenant_id=tenant_id, scan_id=scan_id, agent_ids=set(nodes_by_id))
    edges = view.harness_edges(raw_edges, set(nodes_by_id))
    raw_evidence = {
        (edge.source, edge.target, str(getattr(edge.relationship, "value", edge.relationship))): edge.evidence
        for edge in raw_edges
        if isinstance(edge.evidence, dict)
    }
    placements = view.place_agents(agents, edges)
    order = view.harness_order(placements, nodes_by_id)
    window = order[offset : offset + limit]
    members = {root: view.harness_member_ids(root, placements, nodes_by_id) for root in window}
    harnesses = [view.build_harness(root, placements, nodes_by_id, edges, raw_evidence) for root in window]
    overlay_complete = _overlay(store, tenant_id=tenant_id, scan_id=scan_id, harnesses=harnesses, members=members, nodes_by_id=nodes_by_id)
    reasons = _bound_reasons(agents=agents_complete, edges=edges_complete, overlay=overlay_complete)
    crossing = view.cross_harness_edges(edges, placements, set(window))
    if crossing:
        reasons.append(f"{crossing} declared edge(s) join agents placed in different harnesses and are not shown in either.")
    reasons.extend(reason for harness in harnesses for reason in view.truncation_reasons(harness))
    return {
        "schema_version": "v1",
        "scan_id": scan_id,
        "tenant_id": tenant_id,
        "harnesses": harnesses,
        "summary": view.summary(agents, placements, len(order)),
        "coverage": view.coverage(reasons=reasons, agent_cap=FRAMEWORK_AGENT_CAP),
        "pagination": {"offset": offset, "limit": limit, "total": len(order), "returned": len(harnesses)},
    }


__all__ = ["FRAMEWORK_AGENT_CAP", "read_agent_architecture"]
