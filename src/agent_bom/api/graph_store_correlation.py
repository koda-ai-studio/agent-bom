"""Correlation-run lifecycle for the SQLite graph store."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from agent_bom.api.graph_store_snapshots import SQLiteGraphSnapshotMixin
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph import (
    UnifiedGraph,
)
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun
from agent_bom.graph.ports import GraphStoreProtocol as GraphStoreProtocol


class SQLiteGraphCorrelationMixin(SQLiteGraphSnapshotMixin):
    def create_correlation_run(self, run: GraphCorrelationRun) -> tuple[GraphCorrelationRun, bool]:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            return sqlite_graph_store.create_correlation_run(conn, run)

    def complete_correlation_run(
        self,
        graph: UnifiedGraph,
        *,
        result_manifest: Mapping[str, Any],
        manifest_sha256: str,
        completed_at: str = "",
        execution_owner: str = "",
    ) -> GraphCorrelationRun:
        from agent_bom.graph.correlation import validate_correlation_output_manifest

        validate_correlation_output_manifest(
            graph,
            result_manifest=result_manifest,
            manifest_sha256=manifest_sha256,
        )
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            sqlite_graph_store.save_graph_streaming(
                conn,
                scan_id=graph.scan_id,
                tenant_id=graph.tenant_id,
                created_at=graph.created_at,
                nodes=graph.nodes.values(),
                edges=graph.edges,
                attack_paths=graph.attack_paths,
                interaction_risks=graph.interaction_risks,
                analysis_status=graph.analysis_status,
                snapshot_kind="correlation",
                correlation_id=graph.scan_id,
                evidence_manifest_sha256=manifest_sha256,
                correlation_result_manifest=result_manifest,
                correlation_completed_at=completed_at,
                correlation_execution_owner=execution_owner,
            )
            completed = sqlite_graph_store.get_correlation_run(
                conn,
                tenant_id=graph.tenant_id,
                correlation_id=graph.scan_id,
            )
            if completed is None:  # pragma: no cover - defensive invariant
                raise RuntimeError("completed correlation run disappeared")
            return completed

    def get_correlation_run(self, *, tenant_id: str, correlation_id: str) -> GraphCorrelationRun | None:
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            return sqlite_graph_store.get_correlation_run(conn, tenant_id=tenant_id, correlation_id=correlation_id)
        finally:
            conn.close()

    def get_correlation_run_by_idempotency_key(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
    ) -> GraphCorrelationRun | None:
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            return sqlite_graph_store.get_correlation_run_by_idempotency_key(
                conn,
                tenant_id=tenant_id,
                idempotency_key=idempotency_key,
            )
        finally:
            conn.close()

    def list_correlation_runs(self, *, tenant_id: str, limit: int = 100) -> list[GraphCorrelationRun]:
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.list_correlation_runs(conn, tenant_id=tenant_id, limit=limit)
        finally:
            conn.close()

    def count_active_correlation_runs(self, *, tenant_id: str) -> int:
        conn = self._open_ro_conn()
        if conn is None:
            return 0
        try:
            return sqlite_graph_store.count_active_correlation_runs(conn, tenant_id=tenant_id)
        finally:
            conn.close()

    def claim_correlation_run_execution(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        owner_token: str,
        lease_seconds: int,
        now: str,
    ) -> GraphCorrelationRun | None:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            return sqlite_graph_store.claim_correlation_run_execution(
                conn,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                owner_token=owner_token,
                lease_seconds=lease_seconds,
                now=now,
            )

    def heartbeat_correlation_run_execution(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        owner_token: str,
        lease_seconds: int,
        now: str,
    ) -> bool:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            return sqlite_graph_store.heartbeat_correlation_run_execution(
                conn,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                owner_token=owner_token,
                lease_seconds=lease_seconds,
                now=now,
            )

    def update_correlation_run(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        status: CorrelationRunStatus,
        manifest_sha256: str = "",
        result_manifest: Mapping[str, Any] | None = None,
        output_scan_id: str = "",
        failure_code: str = "",
        started_at: str = "",
        completed_at: str = "",
        execution_owner: str = "",
    ) -> GraphCorrelationRun:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            return sqlite_graph_store.update_correlation_run(
                conn,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                status=status,
                manifest_sha256=manifest_sha256,
                result_manifest=result_manifest,
                output_scan_id=output_scan_id,
                failure_code=failure_code,
                started_at=started_at,
                completed_at=completed_at,
                execution_owner=execution_owner,
            )
