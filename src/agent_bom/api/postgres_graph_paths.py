"""Attack-path and node-context reads for the Postgres graph store."""

from __future__ import annotations

from typing import Any

from agent_bom.db.graph_store import (
    normalize_graph_tenant_id,
)
from agent_bom.db.graph_store_schema import ATTACK_PATH_ORDER, ATTACK_PATH_SELECT
from agent_bom.graph import AttackPath, technique_mappings_from_json
from agent_bom.graph.completeness import (
    graph_completeness,
)
from agent_bom.graph.snapshot_paths import StoredPathSet, StoredQueuePage, path_from_json, queue_filter_sql, stored_paths_current

from .postgres_common import (
    _tenant_connection,
)
from .postgres_graph_support import (
    _decode_json_array,
    _decode_json_object,
)
from .postgres_graph_traversal import PostgresGraphTraversalMixin


def attack_path_from_pg_row(row: Any) -> AttackPath:
    """Decode one row selected with :data:`ATTACK_PATH_SELECT`."""
    return AttackPath(
        source=row[0],
        target=row[1],
        hops=_decode_json_array(row[2], field="attack path nodes"),
        edges=_decode_json_array(row[3], field="attack path edges"),
        composite_risk=row[4],
        summary=row[5] or "",
        credential_exposure=_decode_json_array(row[6], field="attack path credential exposure"),
        tool_exposure=_decode_json_array(row[7], field="attack path tool exposure"),
        vuln_ids=_decode_json_array(row[8], field="attack path vulnerability IDs"),
        reachability=row[9] or "unknown",
        reachability_basis=_decode_json_array(row[10], field="attack path reachability basis"),
        hop_evidence=[dict(item) for item in _decode_json_array(row[12], field="attack path hop evidence") if isinstance(item, dict)],
        analysis=_decode_json_object(row[13], field="attack path analysis"),
        technique_mappings=technique_mappings_from_json(row[11]),
        finding_ids=[str(item) for item in _decode_json_array(row[14], field="attack path finding IDs")],
    )


class PostgresGraphPathsMixin(PostgresGraphTraversalMixin):
    """Read materialised attack paths, incident edge pages and node context."""

    stores_snapshot_paths = True

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
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return None
        where, params = queue_filter_sql(
            placeholder="%s", min_severity=min_severity, has_credential=has_credential, source_type=source_type
        )
        scope = "FROM graph_attack_paths WHERE tenant_id = %s AND scan_id = %s"
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT created_at, analysis_status FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            if row is None or not stored_paths_current(_decode_json_object(row[1], field="graph snapshot analysis status")):
                return None
            snapshot_total = (conn.execute(f"SELECT COUNT(*) {scope}", (tenant_id, effective_scan_id)).fetchone() or (0,))[0]  # nosec B608
            total = (conn.execute(f"SELECT COUNT(*) {scope}{where}", (tenant_id, effective_scan_id, *params)).fetchone() or (0,))[0]  # nosec B608
            rows = conn.execute(
                f"SELECT path_json {scope}{where} ORDER BY queue_rank LIMIT %s OFFSET %s",  # nosec B608 - static predicates
                (tenant_id, effective_scan_id, *params, limit, offset),
            ).fetchall()
        paths = [path_from_json(item[0]) for item in rows]
        return StoredQueuePage(effective_scan_id, str(row[0] or ""), paths, int(total), int(snapshot_total))

    def longest_path_to(self, *, tenant_id: str = "", scan_id: str = "", node_id: str) -> int:
        """Edges on the longest materialized attack path ending at *node_id*; 0 when none does."""
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return 0
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT MAX(json_array_length(path_nodes::json)) FROM attack_paths "
                "WHERE tenant_id = %s AND scan_id = %s AND target_node = %s",
                (tenant_id, effective_scan_id, node_id),
            ).fetchone()
        return max(int(row[0] or 0) - 1, 0) if row else 0

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        if not source_ids:
            return []
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return []
        placeholders = ",".join(["%s"] * len(source_ids))
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"SELECT {ATTACK_PATH_SELECT} FROM attack_paths WHERE tenant_id = %s AND scan_id = %s "  # nosec B608
                f"AND source_node IN ({placeholders}) ORDER BY {ATTACK_PATH_ORDER}",
                [tenant_id, effective_scan_id, *sorted(source_ids)],
            ).fetchall()
        return [attack_path_from_pg_row(row) for row in rows]

    def attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[str, str, list[Any], int]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return scan_id, "", [], 0

        with _tenant_connection(self._pool) as conn:
            snapshot_row = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            total_row = conn.execute(
                "SELECT COUNT(*) FROM attack_paths WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            rows = conn.execute(
                f"SELECT {ATTACK_PATH_SELECT} FROM attack_paths WHERE tenant_id = %s AND scan_id = %s "  # nosec B608
                f"ORDER BY {ATTACK_PATH_ORDER} LIMIT %s OFFSET %s",
                (tenant_id, effective_scan_id, limit, offset),
            ).fetchall()
        return (
            effective_scan_id,
            str(snapshot_row[0]) if snapshot_row else "",
            [attack_path_from_pg_row(row) for row in rows],
            int((total_row[0] if total_row else 0) or 0),
        )

    def incident_edges_page(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        direction: str = "both",
        limit: int = 24,
        cursor: str | None = None,
        snapshot_generation: str | None = None,
    ) -> dict[str, Any] | None:
        """One tenant-scoped MVCC read, without full incident or impact reads."""
        from agent_bom.graph.adjacency_page import incident_edge_page, validate_graph_identifiers

        validate_graph_identifiers(tenant_id, scan_id, node_id, snapshot_generation or "")

        tenant_id = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool, repeatable_read=True) as conn:
            self._apply_search_timeout(conn)
            return incident_edge_page(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                node_id=node_id,
                direction=direction,
                limit=limit,
                cursor=cursor,
                snapshot_generation=snapshot_generation,
                marker="%s",
                node_from_row=self._node_from_row,
                edge_from_row=self._edge_from_row,
            )

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return None
        nodes = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids={node_id})
        if not nodes:
            return None
        with _tenant_connection(self._pool) as conn:
            self._apply_search_timeout(conn)
            rows = conn.execute(
                """
                SELECT source_id, target_id, relationship, direction, weight, traversable,
                       first_seen, last_seen, valid_from, valid_to, confidence, provenance,
                       source_scan_id, source_run_id, evidence, activity_id, scan_id
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s AND (source_id = %s OR target_id = %s)
                ORDER BY source_id, target_id, relationship
                LIMIT 10001
                """,
                (tenant_id, effective_scan_id, node_id, node_id),
            ).fetchall()
        truncated = len(rows) > 10_000
        edges_out: list[Any] = []
        edges_in: list[Any] = []
        neighbors: list[str] = []
        sources: list[str] = []
        for row in rows[:10_000]:
            edge = self._edge_from_row(row)
            if edge.source == node_id:
                edges_out.append(edge)
                neighbors.append(edge.target)
                if edge.is_bidirectional:
                    edges_in.append(self._reverse_edge(edge))
                    sources.append(edge.target)
            if edge.target == node_id:
                edges_in.append(edge)
                sources.append(edge.source)
                if edge.is_bidirectional:
                    edges_out.append(self._reverse_edge(edge))
                    neighbors.append(edge.source)
        return {
            "node": nodes[0],
            "edges_out": edges_out,
            "edges_in": edges_in,
            "neighbors": neighbors,
            "sources": sources,
            "impact": self.impact_of(tenant_id=tenant_id, scan_id=effective_scan_id, node_id=node_id),
            # This used to hand-roll a fourth status word into a vocabulary of
            # three, so the completeness banner — which branches on
            # complete/truncated/sampled and on the booleans — silently ignored
            # it and rendered a bounded neighbourhood as the whole one.
            "completeness": {
                **graph_completeness(
                    returned=len(edges_in) + len(edges_out),
                    truncated=truncated,
                    reason="edge_budget" if truncated else "",
                ),
                "edge_budget": 10_000,
            },
        }
