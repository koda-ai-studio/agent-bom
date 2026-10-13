"""Postgres reads of snapshot-materialized attack paths."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.db.graph_store import normalize_graph_tenant_id
from agent_bom.graph.snapshot_paths import StoredPathSet, path_from_json, stored_paths_current

from .postgres_common import _tenant_connection
from .postgres_graph_support import _decode_json_object


class PostgresSnapshotPathsMixin:
    stores_snapshot_paths = True
    _pool: Any

    if TYPE_CHECKING:

        def latest_snapshot_id(self, *, tenant_id: str = "", snapshot_kind: str = "scan") -> str: ...

    def snapshot_attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str] | None = None,
    ) -> StoredPathSet | None:
        """Ranked stored paths, or ``None`` when the snapshot has no current index."""
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return None
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT created_at, analysis_status FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            if row is None or not stored_paths_current(_decode_json_object(row[1], field="graph snapshot analysis status")):
                return None
            created_at = str(row[0] or "")
            if source_ids is not None and not source_ids:
                return StoredPathSet(effective_scan_id, created_at, [])
            sql = "SELECT path_json FROM graph_attack_paths WHERE tenant_id = %s AND scan_id = %s"
            params: list[Any] = [tenant_id, effective_scan_id]
            if source_ids is not None:
                sql += " AND source_node = ANY(%s)"
                params.append(sorted(source_ids))
            rows = conn.execute(sql + " ORDER BY rank_index", params).fetchall()
        return StoredPathSet(effective_scan_id, created_at, [path_from_json(item[0]) for item in rows])
