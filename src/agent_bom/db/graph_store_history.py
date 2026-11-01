"""Graph snapshot diffs, temporal edge queries and snapshot listings."""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from agent_bom.db.graph_node_aliases import resolve_node_aliases
from agent_bom.db.graph_store_schema import normalize_graph_tenant_id
from agent_bom.graph.analysis import (
    analysis_status_map_from_dict,
    analysis_status_map_to_dict,
)
from agent_bom.graph.diff_identity import edge_lifecycle_diff, edge_set_diff, node_set_diff, snapshot_rename_map
from agent_bom.graph.observation_scope import observation_scope

logger = logging.getLogger("agent_bom.db.graph_store")


def diff_snapshots(
    conn: sqlite3.Connection,
    scan_id_old: str,
    scan_id_new: str,
    *,
    tenant_id: str = "",
) -> dict[str, Any]:
    """Compute the diff between two scan snapshots."""
    from agent_bom.graph.drift_attributes import node_diff_metadata

    tenant_id = normalize_graph_tenant_id(tenant_id)

    def _load_nodes(scan_id: str) -> dict[str, dict[str, Any]]:
        loaded: dict[str, dict[str, Any]] = {}
        for row in conn.execute(
            """
            SELECT id, entity_type, label, status, severity, severity_id, risk_score,
                   attributes, compliance_tags
            FROM graph_nodes
            WHERE scan_id = ? AND tenant_id = ?
            """,
            (scan_id, tenant_id),
        ):
            loaded[row["id"]] = node_diff_metadata(
                node_id=row["id"],
                entity_type=row["entity_type"],
                label=row["label"],
                status=row["status"],
                severity=row["severity"],
                severity_id=int(row["severity_id"] or 0),
                risk_score=float(row["risk_score"] or 0.0),
                attributes=row["attributes"],
                compliance_tags=row["compliance_tags"],
            )
        return loaded

    old_nodes = _load_nodes(scan_id_old)
    new_nodes = _load_nodes(scan_id_new)
    rename = _rename_map(conn, tenant_id, scan_id_new, set(old_nodes) - set(new_nodes), old_ids=set(old_nodes), new_ids=set(new_nodes))

    def _edge_keys(scan_id: str) -> set[tuple[str, str, str]]:
        return {
            (row["source_id"], row["target_id"], row["relationship"])
            for row in conn.execute(
                "SELECT source_id, target_id, relationship FROM graph_edges WHERE scan_id = ? AND tenant_id = ?",
                (scan_id, tenant_id),
            )
        }

    return {
        **node_set_diff(old_nodes, new_nodes, rename),
        **edge_set_diff(_edge_keys(scan_id_old), _edge_keys(scan_id_new), rename),
        "edges_changed": changed_edges_between_scans(conn, scan_id_old, scan_id_new, tenant_id=tenant_id, rename=rename)["edges_changed"],
    }


def _node_ids_in(conn: sqlite3.Connection, tenant_id: str, scan_id: str, ids: list[str]) -> set[str]:
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT id FROM graph_nodes WHERE tenant_id = ? AND scan_id = ? AND id IN ({placeholders})",  # nosec B608 - placeholders only
        [tenant_id, scan_id, *ids],
    ).fetchall()
    return {str(row[0]) for row in rows}


def _rename_map(
    conn: sqlite3.Connection,
    tenant_id: str,
    scan_id_new: str,
    candidates: set[str],
    *,
    old_ids: set[str] | None = None,
    new_ids: set[str] | None = None,
    scan_id_old: str = "",
) -> dict[str, str]:
    """Old-snapshot ids the new snapshot recorded as aliases of one of its nodes."""

    def old_live(ids: list[str]) -> set[str]:
        return set(ids) & old_ids if old_ids is not None else _node_ids_in(conn, tenant_id, scan_id_old, ids)

    def new_live(ids: list[str]) -> set[str]:
        return set(ids) & new_ids if new_ids is not None else _node_ids_in(conn, tenant_id, scan_id_new, ids)

    return snapshot_rename_map(
        candidates,
        resolve=lambda ids: resolve_node_aliases(conn, tenant_id=tenant_id, node_ids=ids, scan_id=scan_id_new),
        old_live=old_live,
        new_live=new_live,
    )


def _edge_history_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "source_id": row["source_id"],
        "target_id": row["target_id"],
        "relationship": row["relationship"],
        "direction": row["direction"],
        "weight": float(row["weight"] or 0.0),
        "traversable": bool(row["traversable"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "valid_from": row["valid_from"] or row["first_seen"],
        "valid_to": row["valid_to"],
        "confidence": float(row["confidence"] if row["confidence"] is not None else 1.0),
        "provenance": {key: value for key, value in json.loads(row["provenance"] or "{}").items() if key != "_agent_bom_canonical_id"},
        "source_scan_id": row["source_scan_id"] or row["scan_id"],
        "source_run_id": row["source_run_id"] or "",
        "evidence": json.loads(row["evidence"] or "{}"),
        "activity_id": int(row["activity_id"] or 1),
        "scan_id": row["scan_id"],
        "tenant_id": row["tenant_id"],
    }


def _edge_change_fingerprint(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "direction": edge["direction"],
        "weight": edge["weight"],
        "traversable": edge["traversable"],
        "confidence": edge["confidence"],
        "provenance": edge["provenance"],
        "evidence": edge["evidence"],
        "activity_id": edge["activity_id"],
    }


def active_edges_at(conn: sqlite3.Connection, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]:
    """Return the latest known edge versions active at an ISO timestamp."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
    rows = conn.execute(
        """
        SELECT ge.*, ns.attributes AS scope_source_attributes, ns.dimensions AS scope_source_dimensions,
               nt.attributes AS scope_target_attributes, nt.dimensions AS scope_target_dimensions
        FROM graph_edges ge
        JOIN graph_snapshots gs ON gs.tenant_id = ge.tenant_id AND gs.scan_id = ge.scan_id
        LEFT JOIN graph_nodes ns ON ns.tenant_id = ge.tenant_id AND ns.scan_id = ge.scan_id AND ns.id = ge.source_id
        LEFT JOIN graph_nodes nt ON nt.tenant_id = ge.tenant_id AND nt.scan_id = ge.scan_id AND nt.id = ge.target_id
        WHERE ge.tenant_id = ?
          AND gs.created_at <= ?
          AND COALESCE(NULLIF(ge.valid_from, ''), ge.first_seen) <= ?
        ORDER BY gs.created_at ASC, ge.scan_id ASC
        """,
        (tenant_id, at, at),
    )
    active_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        edge = _edge_history_row(row)
        scope = observation_scope(
            edge["evidence"],
            row["scope_source_attributes"],
            row["scope_source_dimensions"],
            row["scope_target_attributes"],
            row["scope_target_dimensions"],
        )
        namespace = ("recorded", *scope) if scope is not None else ("snapshot", edge["scan_id"])
        key = (namespace, edge["source_id"], edge["target_id"], edge["relationship"])
        active_by_key[key] = edge
    # Resolve the newest comparable observation before testing its expiry.
    # Filtering expired rows in SQL resurrects an older open-ended version.
    return [edge for key in sorted(active_by_key) if not (edge := active_by_key[key])["valid_to"] or edge["valid_to"] > at]


def changed_edges_between_scans(
    conn: sqlite3.Connection,
    scan_id_old: str,
    scan_id_new: str,
    *,
    tenant_id: str = "",
    rename: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return rich edge lifecycle changes between two scan snapshots.

    Endpoints the new snapshot renamed compare under their new id.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)

    def rows_for(scan_id: str) -> dict[tuple[str, str, str], dict[str, Any]]:
        rows = conn.execute(
            "SELECT * FROM graph_edges WHERE scan_id = ? AND tenant_id = ?",
            (scan_id, tenant_id),
        ).fetchall()
        return {(edge["source_id"], edge["target_id"], edge["relationship"]): edge for edge in (_edge_history_row(row) for row in rows)}

    old_edges = rows_for(scan_id_old)
    new_edges = rows_for(scan_id_new)
    if rename is None:
        gone = set(old_edges) - set(new_edges)
        rename = _rename_map(conn, tenant_id, scan_id_new, {node for key in gone for node in key[:2]}, scan_id_old=scan_id_old)
    return {
        "scan_id_old": scan_id_old,
        "scan_id_new": scan_id_new,
        **edge_lifecycle_diff(old_edges, new_edges, rename, _edge_change_fingerprint),
    }


def list_snapshots(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    limit: int = 50,
    since: str | None = None,
) -> list[dict[str, Any]]:
    """List recent graph snapshots ordered by creation time desc.

    ``since`` (an ISO-8601 cutoff) bounds the result to snapshots created within
    the read window; pass ``None`` to return all retained history.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    where = "WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if since:
        where += " AND created_at >= ?"
        params.append(since)
    params.append(limit)
    rows = conn.execute(
        f"""\
        SELECT scan_id, created_at, node_count, edge_count, risk_summary, analysis_status,
               snapshot_kind, correlation_id, evidence_manifest_sha256
        FROM graph_snapshots
        {where}
        ORDER BY created_at DESC LIMIT ?
        """,  # nosec B608 - where clause is composed from static fragments only
        params,
    ).fetchall()
    return [
        {
            "scan_id": r["scan_id"],
            "created_at": r["created_at"],
            "node_count": r["node_count"],
            "edge_count": r["edge_count"],
            "risk_summary": json.loads(r["risk_summary"]),
            "analysis_status": analysis_status_map_to_dict(analysis_status_map_from_dict(json.loads(r["analysis_status"] or "{}"))),
            "snapshot_kind": r["snapshot_kind"] or "scan",
            "correlation_id": r["correlation_id"] or "",
            "evidence_manifest_sha256": r["evidence_manifest_sha256"] or "",
        }
        for r in rows
    ]


def snapshots_by_ids(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    scan_ids: set[str],
) -> list[dict[str, Any]]:
    """Return exact retained snapshot receipts without a recent-history cap."""

    tenant = normalize_graph_tenant_id(tenant_id)
    selected = sorted({scan_id.strip() for scan_id in scan_ids if scan_id.strip()})
    if not selected:
        return []
    if len(selected) > 32:
        raise ValueError("at most 32 snapshot IDs may be selected")
    placeholders = ",".join("?" for _item in selected)
    rows = conn.execute(
        f"""
        SELECT scan_id, created_at, node_count, edge_count, risk_summary, analysis_status,
               snapshot_kind, correlation_id, evidence_manifest_sha256
        FROM graph_snapshots
        WHERE tenant_id = ? AND scan_id IN ({placeholders})
        ORDER BY scan_id
        """,  # nosec B608 - placeholder count derives only from bounded internal IDs
        [tenant, *selected],
    ).fetchall()
    return [
        {
            "scan_id": row["scan_id"],
            "created_at": row["created_at"],
            "node_count": row["node_count"],
            "edge_count": row["edge_count"],
            "risk_summary": json.loads(row["risk_summary"]),
            "analysis_status": analysis_status_map_to_dict(analysis_status_map_from_dict(json.loads(row["analysis_status"] or "{}"))),
            "snapshot_kind": row["snapshot_kind"] or "scan",
            "correlation_id": row["correlation_id"] or "",
            "evidence_manifest_sha256": row["evidence_manifest_sha256"] or "",
        }
        for row in rows
    ]


def _diff_summary_counts(diff: dict[str, Any]) -> dict[str, int]:
    return {
        "nodes_added": len(diff.get("nodes_added") or []),
        "nodes_removed": len(diff.get("nodes_removed") or []),
        "nodes_changed": len(diff.get("nodes_changed") or []),
        "edges_added": len(diff.get("edges_added") or []),
        "edges_removed": len(diff.get("edges_removed") or []),
        "edges_changed": len(diff.get("edges_changed") or []),
    }
