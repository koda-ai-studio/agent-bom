"""Path, impact and neighbourhood reads for the SQLite graph store."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from agent_bom.api.graph_store_snapshot_paths import SQLiteSnapshotPathsMixin
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.db.graph_store_schema import ATTACK_PATH_ORDER, ATTACK_PATH_SELECT, attack_path_from_row
from agent_bom.graph import (
    AttackPath,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.completeness import (
    bounded_walk_reason,
    impact_completeness,
)
from agent_bom.graph.ports import GraphStoreProtocol as GraphStoreProtocol


class SQLiteGraphTraversalMixin(SQLiteSnapshotPathsMixin):
    if TYPE_CHECKING:

        def _frontier_edge_query(
            self,
            *,
            tenant_id: str,
            scan_id: str,
            frontier: set[str],
            traversable_only: bool = False,
            relationship_types: set[RelationshipType] | None = None,
            static_only: bool = False,
            dynamic_only: bool = False,
        ) -> tuple[str, list[Any]]: ...

        def _walk_graph(
            self,
            conn: sqlite3.Connection,
            *,
            tenant_id: str,
            scan_id: str,
            roots: list[str],
            direction: str,
            max_depth: int,
            max_nodes: int,
            max_edges: int,
            deadline_monotonic: float | None,
            traversable_only: bool,
            relationship_types: set[RelationshipType] | None,
            static_only: bool,
            dynamic_only: bool,
            include_roots: bool,
        ) -> tuple[str, str, set[str], dict[str, int], dict[tuple[str, str, str], UnifiedEdge], dict[str, str], list[str], bool, bool]: ...

    def _filtered_edge_rows(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        frontier: set[str],
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
    ) -> list[sqlite3.Row]:
        """Edges touching the frontier, as two index-anchored reads.

        This is the inner loop of every incremental walk, run once per frontier
        node. It used to be one query with ``(source_id IN (...) OR target_id IN
        (...))``, which SQLite can only serve from the composite indexes as a
        MULTI-INDEX OR — and it only chooses that plan when ``sqlite_stat1`` has
        been populated. On a freshly written store, which has never been
        ``ANALYZE``d, the planner instead prefix-scanned ``(tenant_id, scan_id)``
        and read EVERY edge in the snapshot on EVERY hop: 12,876us per hop on an
        80,181-node snapshot, so a walk that materialised 21 nodes still cost
        time linear in estate size.

        Splitting the OR into a UNION of two single-column lookups makes each
        branch independently index-anchored, so the plan does not depend on
        whether statistics happen to exist: 33us per hop, stats or no stats.
        ``UNION`` (not ``UNION ALL``) because an edge whose both endpoints are in
        the frontier matches both branches.
        """
        if not frontier:
            return []
        sql, params = self._frontier_edge_query(
            tenant_id=tenant_id,
            scan_id=scan_id,
            frontier=frontier,
            traversable_only=traversable_only,
            relationship_types=relationship_types,
            static_only=static_only,
            dynamic_only=dynamic_only,
        )
        return conn.execute(sql, params).fetchall()

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[UnifiedNode]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        if not node_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in node_ids)
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE tenant_id = ? AND scan_id = ? AND id IN ({placeholders})
                """,  # nosec B608 - placeholders are generated internally
                [tenant_id, effective_scan_id, *node_ids],
            ).fetchall()
            return [self._node_from_row(row) for row in rows]
        finally:
            conn.close()

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str], bool, bool]:
        conn = self._open_ro_conn()
        if conn is None:
            return [], set(), False, False
        try:
            (
                _effective_scan_id,
                _created_at,
                visited,
                _depth_by_node,
                _edges,
                parent_by_node,
                discovery_order,
                truncated,
                depth_limited,
            ) = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[source],
                direction="forward",
                max_depth=max_depth,
                max_nodes=5000,
                max_edges=25_000,
                deadline_monotonic=None,
                traversable_only=traversable_only,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
            if source not in visited:
                return [], set(), truncated, depth_limited

            paths: list[list[str]] = []
            for node_id in discovery_order:
                if node_id == source:
                    continue
                path = [node_id]
                current = node_id
                while current in parent_by_node:
                    current = parent_by_node[current]
                    path.append(current)
                path.reverse()
                if path and path[0] == source:
                    paths.append(path)
            reachable = set(visited)
            reachable.discard(source)
            return paths, reachable, truncated, depth_limited
        finally:
            conn.close()

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None:
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id, _created_at, visited, depth_by_node, _edges, _parents, _order, truncated, depth_limited = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[node_id],
                direction="reverse",
                max_depth=max_depth,
                max_nodes=5000,
                max_edges=25_000,
                deadline_monotonic=None,
                traversable_only=False,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
            if not effective_scan_id or node_id not in visited:
                return None

            affected_nodes = sorted(node for node in visited if node != node_id)
            affected_node_rows = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=set(affected_nodes))
            affected_by_type: dict[str, int] = {}
            for node in affected_node_rows:
                entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
                affected_by_type[entity_type] = affected_by_type.get(entity_type, 0) + 1

            return {
                "node_id": node_id,
                "affected_nodes": affected_nodes,
                "affected_by_type": affected_by_type,
                "affected_count": len(affected_nodes),
                "max_depth_reached": max((depth_by_node.get(node, 0) for node in affected_nodes), default=0),
                "completeness": impact_completeness(
                    affected_count=len(affected_nodes),
                    truncated=truncated,
                    depth_limited=depth_limited,
                ),
            }
        finally:
            conn.close()

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        max_edges: int = 10_000,
        deadline_monotonic: float | None = None,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[UnifiedGraph, dict[str, int], bool]:
        # Resolve the tenant up front so the returned graph is labelled with the
        # tenant it was actually read under. `_walk_graph` normalized a local
        # copy while the graph kept the caller's raw string, so a default-tenant
        # traversal came back labelled "" where every other read says "default".
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id), {}, False
        try:
            effective_scan_id, created_at, visited, depth_by_node, traversed_edges, _parents, _order, truncated, depth_limited = (
                self._walk_graph(
                    conn,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    roots=roots,
                    direction=direction,
                    max_depth=max_depth,
                    max_nodes=max_nodes,
                    max_edges=max_edges,
                    deadline_monotonic=deadline_monotonic,
                    traversable_only=traversable_only,
                    relationship_types=relationship_types,
                    static_only=static_only,
                    dynamic_only=dynamic_only,
                    include_roots=include_roots,
                )
            )
            graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=created_at)
            if not effective_scan_id:
                return graph, {}, False
            node_rows = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=visited)
            for node in node_rows:
                graph.add_node(node)
            for edge in traversed_edges.values():
                if edge.source in graph.nodes and edge.target in graph.nodes:
                    graph.add_stored_edge(edge)
            # A bounded walk must say so. #4595 gave the in-memory container and
            # the Postgres store this shape; the default backend was left
            # returning a fresh GraphCompleteness that reads "complete,
            # returned: 0" over a non-empty result. Now that drill-down answers
            # from a traversal, that laundering is reachable from a shipped
            # endpoint. The denominator is the snapshot's recorded node_count --
            # a single-row primary-key lookup, never a COUNT over graph_nodes.
            #
            # Two bounds are reported independently: the node budget and the
            # depth cap. Collapsing them would leave a caller unable to tell
            # whether raising max_depth could recover the missing nodes.
            snapshot_row = conn.execute(
                "SELECT node_count FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            snapshot_nodes = int(snapshot_row["node_count"] or 0) if snapshot_row is not None else 0
            graph.completeness.truncated = truncated
            graph.completeness.depth_limited = depth_limited
            graph.completeness.node_budget = max_nodes if truncated else None
            graph.completeness.reason = bounded_walk_reason(truncated=truncated, depth_limited=depth_limited)
            graph.completeness.total_nodes = snapshot_nodes or len(graph.nodes)
            graph.completeness.returned_nodes = len(graph.nodes)
            return graph, depth_by_node, truncated
        finally:
            conn.close()

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[AttackPath]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        if not source_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in source_ids)
            rows = conn.execute(
                f"SELECT {ATTACK_PATH_SELECT} FROM attack_paths WHERE tenant_id = ? AND scan_id = ? "  # nosec B608
                f"AND source_node IN ({placeholders}) ORDER BY {ATTACK_PATH_ORDER}",
                [tenant_id, effective_scan_id, *source_ids],
            ).fetchall()
            return [attack_path_from_row(row) for row in rows]
        finally:
            conn.close()

    def attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[str, str, list[AttackPath], int]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return scan_id, "", [], 0
        try:
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return scan_id, "", [], 0
            total = conn.execute(
                "SELECT COUNT(*) FROM attack_paths WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT {ATTACK_PATH_SELECT} FROM attack_paths WHERE tenant_id = ? AND scan_id = ? "  # nosec B608
                f"ORDER BY {ATTACK_PATH_ORDER} LIMIT ? OFFSET ?",
                (tenant_id, effective_scan_id, limit, offset),
            ).fetchall()
            return effective_scan_id, created_at, [attack_path_from_row(row) for row in rows], int(total or 0)
        finally:
            conn.close()

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
        """One snapshot read, bounded incident edges, no impact traversal."""
        from agent_bom.graph.adjacency_page import incident_edge_page, validate_graph_identifiers

        validate_graph_identifiers(tenant_id, scan_id, node_id, snapshot_generation or "")

        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            if cursor or snapshot_generation:
                raise ValueError("Incident-edge cursor snapshot is unavailable")
            return None
        try:
            conn.execute("BEGIN")
            return incident_edge_page(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                node_id=node_id,
                direction=direction,
                limit=limit,
                cursor=cursor,
                snapshot_generation=snapshot_generation,
                marker="?",
                node_from_row=self._node_from_row,
                edge_from_row=self._edge_from_row,
            )
        finally:
            conn.close()

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return None
            nodes = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids={node_id})
            if not nodes:
                return None
            rows = conn.execute(
                """
                SELECT *
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ? AND (source_id = ? OR target_id = ?)
                ORDER BY source_id ASC, target_id ASC, relationship ASC
                """,
                [tenant_id, effective_scan_id, node_id, node_id],
            ).fetchall()

            edges_out: list[UnifiedEdge] = []
            edges_in: list[UnifiedEdge] = []
            neighbors: list[str] = []
            sources: list[str] = []

            for row in rows:
                edge = self._edge_from_row(row)
                if edge.source == node_id:
                    edges_out.append(edge)
                    neighbors.append(edge.target)
                    if edge.is_bidirectional:
                        reverse = self._reverse_edge(edge)
                        edges_in.append(reverse)
                        sources.append(edge.target)
                if edge.target == node_id:
                    edges_in.append(edge)
                    sources.append(edge.source)
                    if edge.is_bidirectional:
                        reverse = self._reverse_edge(edge)
                        edges_out.append(reverse)
                        neighbors.append(edge.source)

            return {
                "node": nodes[0],
                "edges_out": edges_out,
                "edges_in": edges_in,
                "neighbors": neighbors,
                "sources": sources,
                "impact": self.impact_of(tenant_id=tenant_id, scan_id=effective_scan_id, node_id=node_id),
            }
        finally:
            conn.close()
