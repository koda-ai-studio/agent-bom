"""Graph snapshot resolution and streamed snapshot reads."""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from agent_bom.graph.delta_digest import PriorSnapshotDigest

from agent_bom.db.graph_store_schema import normalize_graph_tenant_id, normalize_snapshot_kind
from agent_bom.graph import (
    EntityType,
    NodeDimensions,
    NodeStatus,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.container import GraphCompleteness
from agent_bom.graph.severity_floor import severity_floor_sql

logger = logging.getLogger("agent_bom.db.graph_store")


def latest_snapshot_id(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    snapshot_kind: str = "scan",
) -> str:
    """Return the newest same-kind snapshot ID for a tenant, or ``""``."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
    snapshot_kind = normalize_snapshot_kind(snapshot_kind)
    row = conn.execute(
        """\
        SELECT scan_id
        FROM graph_snapshots
        WHERE tenant_id = ? AND snapshot_kind = ?
        ORDER BY created_at DESC, scan_id DESC
        LIMIT 1
        """,
        (tenant_id, snapshot_kind),
    ).fetchone()
    return str(row["scan_id"]) if row else ""


def previous_snapshot_id(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    before_scan_id: str = "",
    snapshot_kind: str = "scan",
) -> str:
    """Return the same-kind snapshot immediately before ``before_scan_id``."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
    snapshot_kind = normalize_snapshot_kind(snapshot_kind)
    if not before_scan_id:
        return ""
    current = conn.execute(
        "SELECT created_at FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ? AND snapshot_kind = ?",
        (tenant_id, before_scan_id, snapshot_kind),
    ).fetchone()
    if not current:
        return ""
    row = conn.execute(
        """\
        SELECT scan_id
        FROM graph_snapshots
        WHERE tenant_id = ? AND snapshot_kind = ? AND created_at < ?
        ORDER BY created_at DESC, scan_id DESC
        LIMIT 1
        """,
        (tenant_id, snapshot_kind, current["created_at"]),
    ).fetchone()
    return str(row["scan_id"]) if row else ""


def _resolve_snapshot(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
) -> tuple[str, str]:
    """Resolve the requested or latest snapshot and return ``(scan_id, created_at)``."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id = scan_id or latest_snapshot_id(conn, tenant_id=tenant_id)
    if not effective_scan_id:
        return "", ""
    row = conn.execute(
        "SELECT created_at FROM graph_snapshots WHERE scan_id = ? AND tenant_id = ?",
        (effective_scan_id, tenant_id),
    ).fetchone()
    if row is None:
        return "", ""
    return effective_scan_id, str(row["created_at"])


def load_rollup_graph(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
) -> UnifiedGraph:
    """Load the complete topology and risk fields used by containment roll-ups.

    This internal projection is only for ``rollup_view``: it deliberately does
    not hydrate evidence, temporal edges, dimensions, or attack paths. Evidence
    and investigation endpoints must continue to use ``load_graph``. No nodes
    or relationships are capped, so aggregate counts retain the full snapshot.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=created_at)
    if not effective_scan_id:
        return graph
    params = (tenant_id, effective_scan_id)
    # Transfer each projection as one JSON batch. sqlite3 releases/reacquires
    # the GIL for every cursor row: concurrent 20k-edge reads otherwise contend
    # tens of thousands of times even after evidence columns are excluded.
    node_batch = conn.execute(
        """SELECT json_group_array(json_array(id, entity_type, label, severity, risk_score, json(attributes)))
           FROM (SELECT id, entity_type, label, severity, risk_score, attributes
                 FROM graph_nodes WHERE tenant_id = ? AND scan_id = ? ORDER BY rowid)""",
        params,
    ).fetchone()
    for node_id, entity_type, label, severity, risk_score, attributes in json.loads(node_batch[0]):
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType(entity_type),
                label=label,
                severity=severity or "",
                risk_score=risk_score,
                attributes=attributes,
                first_seen=created_at,
                last_seen=created_at,
            )
        )
    del node_batch
    edge_batch = conn.execute(
        """SELECT json_group_array(json_array(source_id, target_id, relationship))
           FROM (SELECT source_id, target_id, relationship
                 FROM graph_edges WHERE tenant_id = ? AND scan_id = ?
                 ORDER BY source_id, target_id, relationship)""",
        params,
    ).fetchone()
    for source, target, relationship in json.loads(edge_batch[0]):
        if source in graph.nodes and target in graph.nodes:
            graph.add_edge(
                UnifiedEdge(
                    source=source,
                    target=target,
                    relationship=RelationshipType(relationship),
                    first_seen=created_at,
                    last_seen=created_at,
                )
            )
    del edge_batch
    graph.completeness = GraphCompleteness(total_nodes=len(graph.nodes), returned_nodes=len(graph.nodes))
    return graph


def prior_delta_digest(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
) -> "PriorSnapshotDigest":
    """Build a bounded prior-snapshot digest for delta-alert computation.

    Streams only the columns :func:`agent_bom.graph.webhooks.compute_delta_alerts`
    reads from the prior graph (node ids, agent refs, attack-path and
    interaction-risk keys) instead of materialising a full ``UnifiedGraph`` — so
    peak RSS is decoupled from the prior snapshot's node/edge payload (#4055,
    #4075). The digest yields byte-identical delta alerts to the full-graph path.
    """
    from agent_bom.graph.delta_digest import PriorSnapshotDigestBuilder

    tenant_id = normalize_graph_tenant_id(tenant_id)
    builder = PriorSnapshotDigestBuilder()
    effective_scan_id, _created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return builder.build()
    for row in conn.execute(
        "SELECT id, entity_type, label, severity, status, risk_score, "
        "CASE WHEN entity_type = 'agent' THEN json_extract(attributes, '$.risk_assessment') END AS risk_assessment "
        "FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, effective_scan_id),
    ):
        builder.add_node(
            row["id"],
            row["entity_type"],
            label=row["label"],
            severity=row["severity"] or "",
            status=row["status"],
            risk_score=row["risk_score"],
            risk_assessment=json.loads(row["risk_assessment"]) if row["risk_assessment"] else None,
        )
    for row in conn.execute(
        "SELECT source_node, target_node FROM attack_paths WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, effective_scan_id),
    ):
        builder.add_attack_path(row["source_node"], row["target_node"])
    for row in conn.execute(
        "SELECT pattern, agents FROM interaction_risks WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, effective_scan_id),
    ):
        builder.add_interaction_risk(row["pattern"], json.loads(row["agents"]))
    return builder.build()


def _node_from_snapshot_row(row: sqlite3.Row) -> UnifiedNode:
    return UnifiedNode(
        id=row["id"],
        entity_type=EntityType(row["entity_type"]),
        label=row["label"],
        category_uid=row["category_uid"],
        class_uid=row["class_uid"],
        type_uid=row["type_uid"],
        status=NodeStatus(row["status"]),
        risk_score=row["risk_score"],
        severity=row["severity"] or "",
        severity_id=row["severity_id"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        attributes=json.loads(row["attributes"]),
        compliance_tags=json.loads(row["compliance_tags"]),
        data_sources=json.loads(row["data_sources"]),
        dimensions=NodeDimensions.from_dict(json.loads(row["dimensions"])),
    )


def _edge_from_snapshot_row(row: sqlite3.Row) -> UnifiedEdge:
    return UnifiedEdge(
        source=row["source_id"],
        target=row["target_id"],
        relationship=RelationshipType(row["relationship"]),
        direction=row["direction"],
        weight=row["weight"],
        traversable=bool(row["traversable"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        valid_from=row["valid_from"] or row["first_seen"],
        valid_to=row["valid_to"],
        confidence=row["confidence"],
        provenance=json.loads(row["provenance"] or "{}"),
        source_scan_id=row["source_scan_id"] or row["scan_id"],
        source_run_id=row["source_run_id"] or "",
        evidence=json.loads(row["evidence"]),
        activity_id=row["activity_id"],
    )


def iter_graph_nodes(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    entity_types: set[str] | None = None,
    min_severity_rank: int = 0,
) -> Iterator[UnifiedNode]:
    """Yield a snapshot's nodes one at a time without building a ``UnifiedGraph``.

    Bounded-memory read primitive for callers that genuinely need to iterate the
    whole graph (export, counting, streaming transforms) but do not need the
    adjacency indexes ``load_graph`` builds — peak RSS stays flat as the snapshot
    grows (#4055). ``sqlite3`` streams rows from the cursor lazily.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, _created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return
    query = "SELECT * FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?"
    params: list[Any] = [tenant_id, effective_scan_id]
    if entity_types:
        placeholders = ",".join("?" * len(entity_types))
        query += f" AND entity_type IN ({placeholders})"  # nosec B608 - placeholders are only "?" markers
        params.extend(sorted(entity_types))
    sev_sql, sev_params = severity_floor_sql(min_severity_rank)
    if sev_sql:
        query += f" AND {sev_sql}"  # nosec B608 - fragment is built from a static template
        params.extend(sev_params)
    for row in conn.execute(query, params):
        yield _node_from_snapshot_row(row)


def iter_graph_edges(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    relationship_types: frozenset[str] | None = None,
    node_ids: set[str] | None = None,
) -> Iterator[UnifiedEdge]:
    """Yield a snapshot's edges one at a time without building a ``UnifiedGraph``.

    Endpoint handling — intentionally different from :func:`load_graph`, which
    reconstructs a consistent graph and therefore *always* drops an edge whose
    endpoints are not both in the loaded node set. This is a raw snapshot read:
    when ``node_ids`` is given, only edges whose both endpoints are in that set
    are yielded — reproducing ``load_graph``'s endpoint filter for the case where
    the node stream was itself filtered. When ``node_ids`` is omitted, *every*
    persisted edge is yielded (both endpoints exist by construction for a full
    snapshot; a dangling edge from partial/corrupt data would be yielded here but
    dropped by ``load_graph``). Pass the loaded node-id set to get parity.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, _created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return
    query = "SELECT * FROM graph_edges WHERE tenant_id = ? AND scan_id = ?"
    params: list[Any] = [tenant_id, effective_scan_id]
    if relationship_types:
        placeholders = ",".join("?" * len(relationship_types))
        query += f" AND relationship IN ({placeholders})"  # nosec B608 - placeholders are only "?" markers
        params.extend(sorted(relationship_types))
    for row in conn.execute(query, params):
        if node_ids is not None and (row["source_id"] not in node_ids or row["target_id"] not in node_ids):
            continue
        yield _edge_from_snapshot_row(row)
