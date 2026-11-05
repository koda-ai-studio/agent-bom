"""Postgres side of ending dispatched jobs that nothing will finish."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.api import job_status_count_cache
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.postgres_common import _maintenance_connection, _tenant_connection, bypass_tenant_rls
from agent_bom.api.storage.jobs import require_job_tenant
from agent_bom.config import API_SCAN_MAX_ATTEMPTS

POSTGRES_DISPATCH_QUEUE = """
CREATE TABLE IF NOT EXISTS scan_dispatch_queue (
    job_id           TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    tenant_id        TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    claimed_by       TEXT,
    lease_expires_at TEXT,
    attempts         INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE scan_dispatch_queue ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_dispatch_pending ON scan_dispatch_queue(status, created_at);
"""

# A row owned by the request that holds the report, not by the queue: a dead
# owner's row fails its job, because only that request held the whole payload.
DISPATCH_STATUS_REQUEST = "request"
# A re-admission may take over a dead request's row; a queue-owned row stays with its claim.
ENQUEUE_DISPATCH_SQL = """INSERT INTO scan_dispatch_queue (job_id, tenant_id, created_at, status)
    VALUES (%s, %s, %s, 'pending')
    ON CONFLICT (tenant_id, job_id) DO UPDATE
        SET status = 'pending', claimed_by = NULL, lease_expires_at = NULL, attempts = 0
        WHERE scan_dispatch_queue.status = 'request'"""


def postgres_put_with_request_lease(self: Any, job: ScanJob, claim_owner: str, lease_seconds: int) -> None:
    """Store a job and the lease of the request that owns it, so a crash cannot strand either."""
    with _tenant_connection(self._pool) as conn:
        self._put_on_connection(conn, job)
        conn.execute(
            f"""INSERT INTO scan_dispatch_queue (job_id, tenant_id, created_at, status, claimed_by, lease_expires_at)
                VALUES (%s, %s, %s, '{DISPATCH_STATUS_REQUEST}', %s, {self._LEASE_ISO})
                ON CONFLICT (tenant_id, job_id) DO UPDATE SET
                    status = EXCLUDED.status, claimed_by = EXCLUDED.claimed_by,
                    lease_expires_at = EXCLUDED.lease_expires_at, attempts = 0""",  # nosec B608 - fixed fragments
            (job.job_id, job.tenant_id, job.created_at, claim_owner, int(lease_seconds)),
        )
        conn.commit()
    job_status_count_cache.invalidate_tenant(job.tenant_id)


def postgres_unrecoverable_dispatch_rows(self: Any, max_attempts: int = API_SCAN_MAX_ATTEMPTS, limit: int = 50) -> list[dict[str, Any]]:
    """Expired rows nothing will redeliver: a dead request's, or those out of attempts."""
    with bypass_tenant_rls(audit=False, warn=False):
        with _maintenance_connection(self._maintenance_pool) as conn:
            rows = conn.execute(
                f"""SELECT job_id, tenant_id, status, attempts, claimed_by FROM scan_dispatch_queue
                    WHERE lease_expires_at IS NOT NULL
                      AND lease_expires_at < {self._NOW_ISO}
                      AND (status = '{DISPATCH_STATUS_REQUEST}' OR (status = 'running' AND attempts >= %s))
                    ORDER BY created_at ASC
                    LIMIT %s""",  # nosec B608 - fixed fragments
                (int(max_attempts), int(limit)),
            ).fetchall()
            conn.commit()
    return [dict(zip(("job_id", "tenant_id", "status", "attempts", "claimed_by"), row, strict=True)) for row in rows]


def postgres_stranded_pushed_jobs(self: Any, created_before: datetime, limit: int = 50) -> list[dict[str, str]]:
    """Active pushes with no queue row: nothing owns them, so nothing else will end them."""
    with bypass_tenant_rls(audit=False, warn=False):
        with _maintenance_connection(self._maintenance_pool) as conn:
            rows = conn.execute(
                """SELECT j.job_id, j.team_id FROM scan_jobs j
                   WHERE j.status IN ('pending', 'running')
                     AND COALESCE(j.data->'result'->>'pushed', j.data #>> '{result,summary_projection,fields,pushed}') = 'true'
                     AND j.created_at::timestamptz < %s
                     AND NOT EXISTS (SELECT 1 FROM scan_dispatch_queue q WHERE q.tenant_id = j.team_id AND q.job_id = j.job_id)
                   ORDER BY j.created_at ASC
                   LIMIT %s""",
                (created_before, int(limit)),
            ).fetchall()
            conn.commit()
    return [{"job_id": row[0], "tenant_id": row[1]} for row in rows]


def _still_condemned(self: Any, conn: Any, job_id: str, tenant_id: str, claim_owner: str | None) -> bool:
    if claim_owner is None:
        return (
            conn.execute("SELECT 1 FROM scan_dispatch_queue WHERE tenant_id = %s AND job_id = %s", (tenant_id, job_id)).fetchone() is None
        )
    removed = conn.execute(
        f"""DELETE FROM scan_dispatch_queue
            WHERE tenant_id = %s AND job_id = %s AND claimed_by = %s AND lease_expires_at < {self._NOW_ISO}
            RETURNING 1""",  # nosec B608 - fixed fragment
        (tenant_id, job_id, claim_owner),
    ).fetchone()
    return removed is not None


def postgres_fail_dispatch_job(self: Any, job_id: str, *, tenant_id: str, error: str, claim_owner: str | None) -> ScanJob | None:
    """Fail an active job and drop its expired row together; returns the job only if this call failed it.

    ``claim_owner`` names the expired row that condemned the job, so a renewed
    lease or a peer's sweep turns this into a no-op. ``None`` asserts the job
    has no queue row at all.
    """
    require_job_tenant(tenant_id)
    job = self.get(job_id, tenant_id=tenant_id)
    with _tenant_connection(self._pool) as conn:
        current = conn.execute("SELECT status FROM scan_jobs WHERE team_id = %s AND job_id = %s FOR UPDATE", (tenant_id, job_id)).fetchone()
        condemned = _still_condemned(self, conn, job_id, tenant_id, claim_owner)
        if job is None or current is None or current[0] not in ("pending", "running") or not condemned:
            conn.commit()
            return None
        job.status = JobStatus.FAILED
        job.error = error
        job.completed_at = datetime.now(timezone.utc).isoformat()
        job.progress.append(error)
        self._put_on_connection(conn, job)
        conn.commit()
    job_status_count_cache.invalidate_tenant(tenant_id)
    return job
