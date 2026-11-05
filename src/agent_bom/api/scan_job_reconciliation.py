"""Store-backed reconciliation for scan job lifecycle metrics."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api import metrics
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.scan_batches import refresh_batch_parent
from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.config import API_SCAN_MAX_ATTEMPTS
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)

ACTIVE_SCAN_JOB_STATUSES = frozenset({JobStatus.PENDING, JobStatus.RUNNING})
REQUEST_LOST_ERROR = "Interrupted before completion: the process handling this push stopped. Resubmit the push."


def is_active_scan_job(job: ScanJob) -> bool:
    return job.status in ACTIVE_SCAN_JOB_STATUSES


def active_scan_job_count(store: Any, tenant_id: str | None = None) -> int:
    """Count active jobs through an indexed aggregate, never report blobs."""
    counter = getattr(store, "count_active", None)
    if callable(counter):
        value = counter(tenant_id=tenant_id, all_tenants=tenant_id is None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value

    # Compatibility boundary for third-party stores implementing the older
    # summary protocol. This still avoids selecting/deserializing full reports.
    status_counter = getattr(store, "count_summary_by_status", None)
    if callable(status_counter):
        counts = status_counter(tenant_id=tenant_id)
        if isinstance(counts, dict):
            return sum(int(counts.get(status.value, 0) or 0) for status in ACTIVE_SCAN_JOB_STATUSES)
    raise TypeError("Job store must provide count_active or count_summary_by_status")


def reconcile_scan_jobs_active(store: Any, tenant_id: str | None = None) -> int:
    """Recompute the active scan gauge from the durable job store."""
    count = active_scan_job_count(store, tenant_id=tenant_id)
    metrics.reconcile_scan_jobs_active(count)
    return count


def _parse_created_at(job: ScanJob) -> datetime | None:
    if not job.created_at:
        return None
    try:
        return datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _put_in_job_tenant(store: Any, job: ScanJob) -> None:
    """Persist a globally discovered job through its own tenant-bound app path."""
    run_tenant_bound(job.tenant_id, store.put, job)


def _active_jobs(store: Any) -> Any:
    """Materialize only active candidates, through their own tenant scope."""
    summaries = getattr(store, "list_summary", None)
    if not callable(summaries):
        yield from store.list_all(all_tenants=True)
        return
    for status in ACTIVE_SCAN_JOB_STATUSES:
        for row in summaries(all_tenants=True, status=status):
            tenant = require_explicit_tenant_id(row["tenant_id"])
            job = run_tenant_bound(tenant, store.get, row["job_id"], tenant_id=tenant)
            if job is not None:
                yield job


def _fail_job(store: Any, row: dict[str, Any], error: str, *, claim_owner: str | None) -> int:
    """One condemned job. Its failure must not block the sweep or the claim loop behind it."""
    tenant = require_explicit_tenant_id(row["tenant_id"])
    try:
        job: ScanJob | None = run_tenant_bound(
            tenant, store.fail_dispatch_job, row["job_id"], tenant_id=tenant, error=error, claim_owner=claim_owner
        )
        if job is None:
            return 0
        if job.parent_job_id:
            run_tenant_bound(tenant, refresh_batch_parent, job.parent_job_id, tenant_id=tenant)
    except Exception as exc:  # broad-except: one bad row stays queued for the next sweep; the rest of the queue keeps moving
        _logger.error("Could not fail unrecoverable job=%s: %s", row["job_id"], sanitize_text(sanitize_error(exc, generic=True)))
        return 0
    _logger.warning("Failed unrecoverable job=%s tenant=%s: %s", job.job_id, job.tenant_id, error)
    metrics.record_scan_completion(str(JobStatus.FAILED))
    return 1


def fail_unrecoverable_dispatch_jobs(store: Any, *, max_attempts: int = API_SCAN_MAX_ATTEMPTS) -> int:
    """Fail jobs whose expired lease nothing will redeliver."""
    rows = getattr(store, "unrecoverable_dispatch_rows", None)
    if not callable(rows):
        return 0
    failed = 0
    for row in rows(max_attempts):
        error = (
            f"Gave up after {row['attempts']} attempts: every worker was lost before finishing this job."
            if row["status"] == "running"
            else REQUEST_LOST_ERROR
        )
        failed += _fail_job(store, row, error, claim_owner=row["claimed_by"])
    return failed


def _fail_stranded_pushes(store: Any, *, timeout_seconds: int, now: datetime) -> int:
    """Fail old pushes with no queue row, which no process can be renewing."""
    stranded = getattr(store, "stranded_pushed_jobs", None)
    if not callable(stranded):
        return 0
    return sum(_fail_job(store, row, REQUEST_LOST_ERROR, claim_owner=None) for row in stranded(now - timedelta(seconds=timeout_seconds)))


def fail_stale_active_scan_jobs(
    store: Any,
    *,
    timeout_seconds: int,
    now: datetime | None = None,
    reason: str = "Timed out (stuck in active scan state)",
) -> int:
    """Fail expired local work; distributed work ends on its lease, not on its age."""
    current = now or datetime.now(timezone.utc)
    # Creation age is not a liveness signal. A queued or reclaimed job can be
    # old while its current owner is renewing a valid lease, so only an expired
    # lease condemns a queue row. Age applies only to a push with no row at all,
    # which no process can be renewing.
    if distributed_scans_enabled() and store_supports_dispatch(store):
        return fail_unrecoverable_dispatch_jobs(store) + _fail_stranded_pushes(store, timeout_seconds=timeout_seconds, now=current)
    failed = 0
    for job in _active_jobs(store):
        if not is_active_scan_job(job):
            continue
        created = _parse_created_at(job)
        if created is None:
            continue
        if (current - created).total_seconds() <= timeout_seconds:
            continue
        require_explicit_tenant_id(job.tenant_id)
        job.status = JobStatus.FAILED
        job.error = reason
        job.completed_at = current.isoformat()
        _put_in_job_tenant(store, job)
        failed += 1
    return failed


def fail_orphaned_active_scan_jobs(
    store: Any,
    *,
    reason: str = "Interrupted before completion; in-process executor state was lost",
) -> int:
    """Fail orphaned in-process jobs without invalidating shared dispatch jobs.

    Local executor state does not survive restart. Distributed dispatch instead
    owns pending jobs and running leases across replicas; a newly started
    replica must leave those jobs to the current worker or lease reclaimer.
    """
    if distributed_scans_enabled() and store_supports_dispatch(store):
        return 0
    now = datetime.now(timezone.utc)
    failed = 0
    for job in _active_jobs(store):
        if not is_active_scan_job(job):
            continue
        require_explicit_tenant_id(job.tenant_id)
        job.status = JobStatus.FAILED
        job.error = reason
        job.completed_at = now.isoformat()
        _put_in_job_tenant(store, job)
        failed += 1
    return failed
