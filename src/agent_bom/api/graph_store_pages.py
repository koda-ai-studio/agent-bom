"""Paged node, inventory-context, edge and filter-preset reads for the SQLite graph store."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from agent_bom.api.graph_edge_query import edge_query
from agent_bom.api.graph_store_correlation import SQLiteGraphCorrelationMixin
from agent_bom.api.graph_store_support import (
    _assert_offset_within_cap,
    decode_graph_cursor,
    encode_graph_cursor,
)
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph import (
    UnifiedNode,
)
from agent_bom.graph.ports import GraphStoreProtocol as GraphStoreProtocol
from agent_bom.graph.severity_floor import severity_floor_sql


class SQLiteGraphPagesMixin(SQLiteGraphCorrelationMixin):
    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int, str | None]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        _assert_offset_within_cap(offset, cursor)
        conn = self._open_ro_conn()
        if conn is None:
            return scan_id, "", [], 0, None
        try:
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return scan_id, "", [], 0, None
            where = ["tenant_id = ?", "scan_id = ?"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join("?" for _ in entity_types)
                where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            sev_sql, sev_params = severity_floor_sql(min_severity_rank)
            if sev_sql:
                where.append(sev_sql)
                params.extend(sev_params)
            where_sql = " AND ".join(where)
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchone()[0]
                or 0
            )
            row_params = list(params)
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                AND (
                    severity_id < ?
                    OR (severity_id = ? AND risk_score < ?)
                    OR (severity_id = ? AND risk_score = ? AND label > ?)
                    OR (severity_id = ? AND risk_score = ? AND label = ? AND id > ?)
                )
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE {where_sql}
                {cursor_clause}
                ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                LIMIT ? OFFSET ?
                """,  # nosec B608 - where_sql is built from static clause fragments
                [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit if cursor else offset + limit < total
            rows = rows[:limit]
            nodes = [self._node_from_row(row) for row in rows]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
            return effective_scan_id, created_at, nodes, total, next_cursor
        finally:
            conn.close()

    @staticmethod
    def _empty_inventory_result(*, scan_id: str) -> dict[str, Any]:
        return {
            "scan_id": scan_id,
            "created_at": "",
            "nodes": [],
            "total": 0,
            "next_cursor": None,
            "facets": {name: [] for name in ("type", "source", "provider", "environment", "severity")},
            "finding_summaries": {},
            "relationship_counts": {},
            "finding_count": 0,
        }

    def _inventory_page_context(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        node_ids: set[str],
        finding_types: list[str],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
        if not node_ids:
            return {}, {}
        node_values = sorted(node_ids)
        node_marks = ",".join("?" for _ in node_values)
        finding_marks = ",".join("?" for _ in finding_types)
        rows = conn.execute(
            f"""
                SELECT a.id, f.id,
                       CASE LOWER(COALESCE(f.severity, '')) WHEN 'informational' THEN 'info'
                            ELSE LOWER(COALESCE(f.severity, '')) END
                FROM graph_nodes a
                JOIN graph_edges e ON e.tenant_id = a.tenant_id AND e.scan_id = a.scan_id
                    AND (e.source_id = a.id OR e.target_id = a.id)
                JOIN graph_nodes f ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id
                    AND f.id = CASE WHEN e.source_id = a.id THEN e.target_id ELSE e.source_id END
                WHERE a.tenant_id = ? AND a.scan_id = ? AND a.id IN ({node_marks})
                  AND f.entity_type IN ({finding_marks})
                GROUP BY a.id, f.id, f.severity
                ORDER BY a.id, f.severity_id DESC, f.id
            """,  # nosec B608 - placeholder lists only
            [tenant_id, scan_id, *node_values, *finding_types],
        ).fetchall()
        summaries: dict[str, dict[str, Any]] = {}
        for asset_id, finding_id, finding_severity in rows:
            summary = summaries.setdefault(str(asset_id), {"total": 0, "by_severity": {}, "ids": [], "top_severity": ""})
            summary["total"] += 1
            summary["ids"].append(str(finding_id))
            if finding_severity:
                by_severity = summary["by_severity"]
                by_severity[str(finding_severity)] = int(by_severity.get(str(finding_severity), 0)) + 1
                if not summary["top_severity"]:
                    summary["top_severity"] = str(finding_severity)
        relationship_rows = conn.execute(
            f"""
                SELECT node_id, COUNT(*) FROM (
                    SELECT source_id AS node_id, source_id, target_id, relationship FROM graph_edges
                    WHERE tenant_id = ? AND scan_id = ? AND source_id IN ({node_marks})
                    UNION
                    SELECT target_id AS node_id, source_id, target_id, relationship FROM graph_edges
                    WHERE tenant_id = ? AND scan_id = ? AND target_id IN ({node_marks})
                ) GROUP BY node_id
            """,  # nosec B608 - placeholder lists only
            [tenant_id, scan_id, *node_values, tenant_id, scan_id, *node_values],
        ).fetchall()
        return summaries, {str(row[0]): int(row[1]) for row in relationship_rows}

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
        induced_only: bool = False,
        direction: str = "both",
        relationships: set[str] | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        if not node_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return []
            query, params = edge_query(
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                node_ids=node_ids,
                induced_only=induced_only,
                direction=direction,
                relationships=relationships,
                limit=limit,
            )
            rows = conn.execute(query, params).fetchall()
            return [self._edge_from_row(row) for row in rows]
        finally:
            conn.close()

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        with self._write_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO graph_filter_presets VALUES (?, ?, ?, ?, ?)",
                (name, tenant_id, description, json.dumps(filters), created_at),
            )
            conn.commit()

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            rows = conn.execute(
                "SELECT name, description, filters, created_at FROM graph_filter_presets WHERE tenant_id = ? ORDER BY name",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "name": row["name"],
                    "description": row["description"],
                    "filters": json.loads(row["filters"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def delete_preset(self, *, tenant_id: str, name: str) -> bool:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        with self._write_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM graph_filter_presets WHERE name = ? AND tenant_id = ?",
                (name, tenant_id),
            )
            conn.commit()
            return cursor.rowcount > 0
