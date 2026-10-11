"""Graph correlation-run persistence."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    pass

from agent_bom.db.graph_store_schema import normalize_graph_tenant_id
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun, validate_correlation_update

logger = logging.getLogger("agent_bom.db.graph_store")


def _correlation_run_from_row(row: sqlite3.Row) -> GraphCorrelationRun:
    return GraphCorrelationRun.from_mapping(
        {
            "correlation_id": row["correlation_id"],
            "tenant_id": row["tenant_id"],
            "idempotency_key": row["idempotency_key"],
            "name": row["name"],
            "status": row["status"],
            "max_age_hours": row["max_age_hours"],
            "allow_stale": bool(row["allow_stale"]),
            "input_manifest": json.loads(row["input_manifest"] or "[]"),
            "result_manifest": json.loads(row["result_manifest"] or "{}"),
            "manifest_sha256": row["manifest_sha256"],
            "output_scan_id": row["output_scan_id"],
            "failure_code": row["failure_code"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "execution_owner": row["execution_owner"],
            "execution_lease_expires_at": row["execution_lease_expires_at"],
        }
    )


def get_correlation_run(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    correlation_id: str,
) -> GraphCorrelationRun | None:
    tenant = normalize_graph_tenant_id(tenant_id)
    row = conn.execute(
        "SELECT * FROM graph_correlation_runs WHERE tenant_id = ? AND correlation_id = ?",
        (tenant, correlation_id),
    ).fetchone()
    return _correlation_run_from_row(row) if row is not None else None


def get_correlation_run_by_idempotency_key(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    idempotency_key: str,
) -> GraphCorrelationRun | None:
    tenant = normalize_graph_tenant_id(tenant_id)
    row = conn.execute(
        "SELECT * FROM graph_correlation_runs WHERE tenant_id = ? AND idempotency_key = ?",
        (tenant, idempotency_key),
    ).fetchone()
    return _correlation_run_from_row(row) if row is not None else None


def create_correlation_run(
    conn: sqlite3.Connection,
    run: GraphCorrelationRun,
) -> tuple[GraphCorrelationRun, bool]:
    """Create an immutable request or return its tenant-scoped idempotent replay."""

    tenant = normalize_graph_tenant_id(run.tenant_id)
    existing = conn.execute(
        "SELECT * FROM graph_correlation_runs WHERE tenant_id = ? AND idempotency_key = ?",
        (tenant, run.idempotency_key),
    ).fetchone()
    if existing is not None:
        replay = _correlation_run_from_row(existing)
        if replay.request_fingerprint() != run.request_fingerprint():
            raise ValueError("idempotency key was already used for a different correlation request")
        return replay, False
    collision = get_correlation_run(conn, tenant_id=tenant, correlation_id=run.correlation_id)
    if collision is not None:
        raise ValueError("correlation_id already exists with a different idempotency key")
    conn.execute(
        """
        INSERT INTO graph_correlation_runs (
            correlation_id, tenant_id, idempotency_key, name, status,
            max_age_hours, allow_stale, input_manifest, manifest_sha256,
            result_manifest, output_scan_id, failure_code, created_at, started_at, completed_at,
            execution_owner, execution_lease_expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run.correlation_id,
            tenant,
            run.idempotency_key,
            run.name,
            run.status.value,
            run.max_age_hours,
            int(run.allow_stale),
            json.dumps(run.input_manifest, sort_keys=True, separators=(",", ":")),
            run.manifest_sha256,
            json.dumps(run.result_manifest, sort_keys=True, separators=(",", ":")),
            run.output_scan_id,
            run.failure_code,
            run.created_at,
            run.started_at,
            run.completed_at,
            run.execution_owner,
            run.execution_lease_expires_at,
        ),
    )
    conn.commit()
    created = get_correlation_run(conn, tenant_id=tenant, correlation_id=run.correlation_id)
    if created is None:  # pragma: no cover - defensive persistence invariant
        raise RuntimeError("correlation run was not persisted")
    return created, True


def list_correlation_runs(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    limit: int = 100,
) -> list[GraphCorrelationRun]:
    tenant = normalize_graph_tenant_id(tenant_id)
    rows = conn.execute(
        "SELECT * FROM graph_correlation_runs WHERE tenant_id = ? ORDER BY created_at DESC, correlation_id DESC LIMIT ?",
        (tenant, max(1, min(int(limit), 1000))),
    ).fetchall()
    return [_correlation_run_from_row(row) for row in rows]


def count_active_correlation_runs(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
) -> int:
    """Count pending/running correlations without materializing run history."""

    tenant = normalize_graph_tenant_id(tenant_id)
    row = conn.execute(
        "SELECT COUNT(*) FROM graph_correlation_runs WHERE tenant_id = ? AND status IN (?, ?)",
        (
            tenant,
            CorrelationRunStatus.PENDING.value,
            CorrelationRunStatus.RUNNING.value,
        ),
    ).fetchone()
    return int(row[0]) if row is not None else 0


def claim_correlation_run_execution(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    correlation_id: str,
    owner_token: str,
    lease_seconds: int,
    now: str,
) -> GraphCorrelationRun | None:
    """Lease one pending or abandoned run to exactly one worker replica."""

    tenant = normalize_graph_tenant_id(tenant_id)
    started = datetime.fromisoformat(now)
    expires = (started + timedelta(seconds=max(1, int(lease_seconds)))).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        cursor = conn.execute(
            """
            UPDATE graph_correlation_runs
            SET status = ?, started_at = CASE WHEN started_at = '' THEN ? ELSE started_at END,
                execution_owner = ?, execution_lease_expires_at = ?
            WHERE tenant_id = ? AND correlation_id = ?
              AND (status = ? OR (status = ? AND execution_lease_expires_at <= ?))
            """,
            (
                CorrelationRunStatus.RUNNING.value,
                now,
                owner_token,
                expires,
                tenant,
                correlation_id,
                CorrelationRunStatus.PENDING.value,
                CorrelationRunStatus.RUNNING.value,
                now,
            ),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return None
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return get_correlation_run(conn, tenant_id=tenant, correlation_id=correlation_id)


def heartbeat_correlation_run_execution(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    correlation_id: str,
    owner_token: str,
    lease_seconds: int,
    now: str,
) -> bool:
    expires = (datetime.fromisoformat(now) + timedelta(seconds=max(1, int(lease_seconds)))).isoformat()
    cursor = conn.execute(
        """
        UPDATE graph_correlation_runs SET execution_lease_expires_at = ?
        WHERE tenant_id = ? AND correlation_id = ? AND status = ? AND execution_owner = ?
        """,
        (
            expires,
            normalize_graph_tenant_id(tenant_id),
            correlation_id,
            CorrelationRunStatus.RUNNING.value,
            owner_token,
        ),
    )
    conn.commit()
    return cursor.rowcount == 1


def update_correlation_run(
    conn: sqlite3.Connection,
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
    existing = get_correlation_run(conn, tenant_id=tenant_id, correlation_id=correlation_id)
    if existing is None:
        raise KeyError("correlation run not found")
    resolved_manifest, resolved_result_manifest, resolved_output, resolved_failure = validate_correlation_update(
        existing,
        status=status,
        manifest_sha256=manifest_sha256,
        result_manifest=result_manifest,
        output_scan_id=output_scan_id,
        failure_code=failure_code,
    )
    conn.execute(
        """
        UPDATE graph_correlation_runs
        SET status = ?, manifest_sha256 = ?, result_manifest = ?, output_scan_id = ?, failure_code = ?,
            started_at = ?, completed_at = ?
        WHERE tenant_id = ? AND correlation_id = ?
          AND (? = '' OR execution_owner = ?)
        """,
        (
            status.value,
            resolved_manifest,
            json.dumps(resolved_result_manifest, sort_keys=True, separators=(",", ":")),
            resolved_output,
            resolved_failure,
            started_at or existing.started_at,
            completed_at or existing.completed_at,
            normalize_graph_tenant_id(tenant_id),
            correlation_id,
            execution_owner,
            execution_owner,
        ),
    )
    if conn.execute("SELECT changes()").fetchone()[0] != 1:
        raise ValueError("correlation execution lease is not owned")
    conn.commit()
    updated = get_correlation_run(conn, tenant_id=tenant_id, correlation_id=correlation_id)
    if updated is None:  # pragma: no cover - defensive persistence invariant
        raise RuntimeError("correlation run disappeared after update")
    return updated
