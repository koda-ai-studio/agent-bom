"""SQLite reads of snapshot-materialized attack paths."""

from __future__ import annotations

import json
import sqlite3

from agent_bom.api.graph_store_base import SQLiteGraphStoreBase
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph.snapshot_paths import StoredPathSet, StoredQueuePage, path_from_json, queue_filter_sql, stored_paths_current


class SQLiteSnapshotPathsMixin(SQLiteGraphStoreBase):
    stores_snapshot_paths = True

    def snapshot_attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str] | None = None,
    ) -> StoredPathSet | None:
        """Ranked stored paths, or ``None`` when the snapshot has no current index."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            row = conn.execute(
                "SELECT created_at, analysis_status FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            if row is None or not stored_paths_current(json.loads(row["analysis_status"] or "{}")):
                return None
            sql = "SELECT path_json FROM graph_attack_paths WHERE tenant_id = ? AND scan_id = ?"
            params: list[str] = [tenant_id, effective_scan_id]
            if source_ids is not None:
                if not source_ids:
                    return StoredPathSet(effective_scan_id, str(row["created_at"]), [])
                sql += f" AND source_node IN ({','.join('?' for _ in source_ids)})"
                params.extend(sorted(source_ids))
            rows = conn.execute(sql + " ORDER BY rank_index", params).fetchall()  # nosec B608 - placeholders only
            return StoredPathSet(effective_scan_id, str(row["created_at"]), [path_from_json(item["path_json"]) for item in rows])
        except sqlite3.OperationalError:
            return None
        finally:
            conn.close()

    def snapshot_queue_page(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        offset: int = 0,
        limit: int = 100,
        min_severity: str | None = None,
        has_credential: bool | None = None,
        source_type: str | None = None,
    ) -> StoredQueuePage | None:
        """One queue page in stored queue order, or ``None`` without a current index."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            row = conn.execute(
                "SELECT created_at, analysis_status FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            if row is None or not stored_paths_current(json.loads(row["analysis_status"] or "{}")):
                return None
            where, params = queue_filter_sql(
                placeholder="?", min_severity=min_severity, has_credential=has_credential, source_type=source_type
            )
            scope = "FROM graph_attack_paths WHERE tenant_id = ? AND scan_id = ?"
            snapshot_total = conn.execute(f"SELECT COUNT(*) {scope}", (tenant_id, effective_scan_id)).fetchone()[0]  # nosec B608
            total = conn.execute(f"SELECT COUNT(*) {scope}{where}", (tenant_id, effective_scan_id, *params)).fetchone()[0]  # nosec B608
            rows = conn.execute(
                f"SELECT path_json {scope}{where} ORDER BY queue_rank LIMIT ? OFFSET ?",  # nosec B608 - static predicates
                (tenant_id, effective_scan_id, *params, limit, offset),
            ).fetchall()
            paths = [path_from_json(item["path_json"]) for item in rows]
            return StoredQueuePage(effective_scan_id, str(row["created_at"]), paths, int(total), int(snapshot_total))
        except sqlite3.OperationalError:
            return None
        finally:
            conn.close()
