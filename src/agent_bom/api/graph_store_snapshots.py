"""Snapshot persistence, history and diff reads for the SQLite graph store."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.graph.delta_digest import PriorSnapshotDigest

from agent_bom.api.graph_store_support import (
    _API_GRAPH_TENANT_TABLE_KEYS,
    _CREATE_PRESET_TABLE_SQLITE,
)
from agent_bom.api.graph_store_traversal import SQLiteGraphTraversalMixin
from agent_bom.api.storage.sqlite_graph_search import ensure_search_index
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.db.graph_revision import read_snapshot_identity
from agent_bom.graph import (
    AttackPath,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.analysis import GraphAnalysisStatus
from agent_bom.graph.ports import GraphStoreProtocol as GraphStoreProtocol
from agent_bom.graph.snapshot_paths import SnapshotPath


class SQLiteGraphSnapshotMixin(SQLiteGraphTraversalMixin):
    def snapshot_identity(self, *, tenant_id: str = "", scan_id: str = "", for_paging: bool = False) -> tuple[str, str]:
        """Resolve one durable snapshot generation, including latest, atomically."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return scan_id, ""
        try:
            return read_snapshot_identity(conn, tenant_id, scan_id, for_paging, "?")
        finally:
            conn.close()

    def latest_snapshot_id(self, *, tenant_id: str = "", snapshot_kind: str = "scan") -> str:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return ""
        try:
            return sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id, snapshot_kind=snapshot_kind)
        finally:
            conn.close()

    def previous_snapshot_id(
        self,
        *,
        tenant_id: str = "",
        before_scan_id: str = "",
        snapshot_kind: str = "scan",
    ) -> str:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return ""
        try:
            return sqlite_graph_store.previous_snapshot_id(
                conn,
                tenant_id=tenant_id,
                before_scan_id=before_scan_id,
                snapshot_kind=snapshot_kind,
            )
        finally:
            conn.close()

    def save_graph(self, graph: UnifiedGraph) -> None:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(_CREATE_PRESET_TABLE_SQLITE)
            ensure_search_index(conn)
            sqlite_graph_store.save_graph(conn, graph)
            sqlite_graph_store._backfill_empty_tenant_ids(conn, _API_GRAPH_TENANT_TABLE_KEYS)
            conn.commit()

    def save_graph_streaming(
        self,
        *,
        scan_id: str,
        tenant_id: str = "",
        nodes: Iterable[UnifiedNode],
        edges: Iterable[UnifiedEdge],
        attack_paths: Iterable[AttackPath] = (),
        interaction_risks: Iterable[Any] = (),
        analysis_status: Mapping[str, GraphAnalysisStatus] | None = None,
        created_at: str = "",
        snapshot_kind: str = "scan",
        correlation_id: str = "",
        evidence_manifest_sha256: str = "",
        write_generation: str = "",
        snapshot_paths: Sequence[SnapshotPath] | None = None,
    ) -> dict[str, int]:
        """Persist a snapshot from node/edge iterables without materialising a graph.

        Bounded-memory equivalent of :meth:`save_graph` (#4055): peak RSS is
        decoupled from graph size for producers that yield nodes/edges lazily.
        """
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(_CREATE_PRESET_TABLE_SQLITE)
            ensure_search_index(conn)
            counts = sqlite_graph_store.save_graph_streaming(
                conn,
                scan_id=scan_id,
                tenant_id=tenant_id,
                nodes=nodes,
                edges=edges,
                attack_paths=attack_paths,
                interaction_risks=interaction_risks,
                analysis_status=analysis_status,
                created_at=created_at,
                snapshot_kind=snapshot_kind,
                correlation_id=correlation_id,
                evidence_manifest_sha256=evidence_manifest_sha256,
                write_generation=write_generation,
                snapshot_paths=snapshot_paths,
            )
            sqlite_graph_store._backfill_empty_tenant_ids(conn, _API_GRAPH_TENANT_TABLE_KEYS)
            conn.commit()
            return counts

    def iter_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> Iterator[UnifiedNode]:
        """Yield a snapshot's nodes without building the whole graph in memory."""
        conn = self._open_ro_conn()
        if conn is None:
            return
        try:
            yield from sqlite_graph_store.iter_graph_nodes(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                entity_types=entity_types,
                min_severity_rank=min_severity_rank,
            )
        finally:
            conn.close()

    def iter_edges(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        relationship_types: frozenset[str] | None = None,
        node_ids: set[str] | None = None,
    ) -> Iterator[UnifiedEdge]:
        """Yield a snapshot's edges without building the whole graph in memory."""
        conn = self._open_ro_conn()
        if conn is None:
            return
        try:
            yield from sqlite_graph_store.iter_graph_edges(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                relationship_types=relationship_types,
                node_ids=node_ids,
            )
        finally:
            conn.close()

    def load_rollup_graph(self, *, tenant_id: str = "", scan_id: str = "") -> UnifiedGraph:
        """Internal complete-topology projection; never use for evidence exports."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
        try:
            # Resolve the snapshot, nodes, and edges in one read transaction;
            # a concurrent refresh must not splice together two revisions.
            conn.execute("BEGIN")
            return sqlite_graph_store.load_rollup_graph(conn, tenant_id=tenant_id, scan_id=scan_id)
        finally:
            conn.close()

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        relationship_types: frozenset[str] | None = None,
        node_budget: int | None = None,
    ) -> UnifiedGraph:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
        try:
            # The budget is pushed into the query, as Postgres does: bounding
            # after materialization declared the right completeness while still
            # having read every row.
            return sqlite_graph_store.load_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                entity_types=entity_types,
                min_severity_rank=min_severity_rank,
                relationship_types=relationship_types,
                node_budget=node_budget,
            )
        finally:
            conn.close()

    def prior_delta_digest(self, *, tenant_id: str = "", scan_id: str = "") -> "PriorSnapshotDigest":
        """Bounded prior-snapshot digest for delta alerts (see #4055/#4075)."""
        from agent_bom.graph.delta_digest import PriorSnapshotDigestBuilder

        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return PriorSnapshotDigestBuilder().build()
        try:
            return sqlite_graph_store.prior_delta_digest(conn, tenant_id=tenant_id, scan_id=scan_id)
        finally:
            conn.close()

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "nodes_added": [],
                "nodes_removed": [],
                "nodes_changed": [],
                "edges_added": [],
                "edges_removed": [],
            }
        try:
            return sqlite_graph_store.diff_snapshots(conn, scan_id_old, scan_id_new, tenant_id=tenant_id)
        finally:
            conn.close()

    def active_edges_at(self, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.active_edges_at(conn, at, tenant_id=tenant_id)
        finally:
            conn.close()

    def changed_edges_between_scans(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "scan_id_old": scan_id_old,
                "scan_id_new": scan_id_new,
                "edges_added": [],
                "edges_removed": [],
                "edges_changed": [],
                "edges_unchanged": [],
                "summary": {"added": 0, "removed": 0, "changed": 0, "unchanged": 0},
            }
        try:
            return sqlite_graph_store.changed_edges_between_scans(conn, scan_id_old, scan_id_new, tenant_id=tenant_id)
        finally:
            conn.close()

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> list[dict[str, Any]]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.list_snapshots(conn, tenant_id=tenant_id, limit=limit, since=since)
        finally:
            conn.close()

    def snapshots_by_ids(self, *, tenant_id: str, scan_ids: set[str]) -> list[dict[str, Any]]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.snapshots_by_ids(conn, tenant_id=tenant_id, scan_ids=scan_ids)
        finally:
            conn.close()

    def graph_history(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "schema_version": "agent-bom.graph_history/v1",
                "tenant_id": tenant_id,
                "retention_policy": sqlite_graph_store.graph_retention_policy(),
                "snapshots": [],
            }
        try:
            return sqlite_graph_store.graph_history(conn, tenant_id=tenant_id, limit=limit, since=since)
        finally:
            conn.close()

    def evidence_manifest(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        baseline_scan_id: str = "",
    ) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "schema_version": "agent-bom.graph_evidence_manifest/v1",
                "tenant_id": tenant_id,
                "scan_id": "",
                "generated_at": "",
                "retention_policy": sqlite_graph_store.graph_retention_policy(),
                "included_tables": [
                    "graph_snapshots",
                    "graph_nodes",
                    "graph_edges",
                    "attack_paths",
                    "interaction_risks",
                ],
                "excluded_private_fields": [
                    "graph_nodes.attributes",
                    "graph_edges.provenance",
                    "graph_edges.evidence",
                    "attack_paths.credential_exposure",
                ],
            }
        try:
            return sqlite_graph_store.graph_evidence_manifest(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                baseline_scan_id=baseline_scan_id,
            )
        finally:
            conn.close()
