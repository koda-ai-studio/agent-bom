"""SQLite reads of snapshot-materialized attack paths."""

from __future__ import annotations

import json
import sqlite3

from agent_bom.api.graph_store_base import SQLiteGraphStoreBase
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph.snapshot_paths import StoredPathSet, path_from_json, stored_paths_current


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
