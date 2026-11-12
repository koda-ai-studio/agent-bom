"""Scan worker dispatch and persisted batch repair."""

from __future__ import annotations

import logging
from typing import cast

from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.pipeline import submit_scan_job
from agent_bom.api.scan_batches import child_request_for_target, scan_request_targets
from agent_bom.api.stores import _get_store, _jobs_put
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)


def _repair_scan_batch(parent: ScanJob, *, dispatch: bool = True) -> ScanJob:
    """Reconstruct missing durable children from an immutable batch parent.

    Older writers persisted the parent and children sequentially. A process
    death could therefore leave a durable parent whose idempotent replay was
    treated as complete. The parent contains the exact child IDs and request,
    so retries can safely repair only absent rows without minting new work.
    """

    if not parent.child_job_ids:
        return parent
    targets = scan_request_targets(parent.request)
    if len(targets) != len(parent.child_job_ids):
        raise RuntimeError("Persisted scan batch membership is invalid.")
    store = _get_store()
    missing: list[ScanJob] = []
    for index, (child_id, target) in enumerate(zip(parent.child_job_ids, targets, strict=True), start=1):
        child = cast(ScanJob | None, store.get(child_id, tenant_id=parent.tenant_id))
        if child is None:
            missing.append(
                ScanJob(
                    job_id=child_id,
                    tenant_id=parent.tenant_id,
                    batch_id=parent.batch_id,
                    parent_job_id=parent.job_id,
                    target=target,
                    target_index=index,
                    target_count=len(targets),
                    source_id=parent.source_id,
                    schedule_id=parent.schedule_id,
                    triggered_by=parent.triggered_by,
                    created_at=parent.created_at,
                    request=child_request_for_target(parent.request, target),
                )
            )
            continue
        if (
            child.tenant_id != parent.tenant_id
            or child.parent_job_id != parent.job_id
            or child.batch_id != parent.batch_id
            or child.target != target
            or child.target_index != index
            or child.target_count != len(targets)
        ):
            raise RuntimeError("Persisted scan batch membership is invalid.")
    if missing:
        atomic_repair = getattr(store, "put_many_if_absent_and_enqueue_atomic", None)
        from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch

        if dispatch and distributed_scans_enabled() and store_supports_dispatch(store) and callable(atomic_repair):
            inserted_ids = set(atomic_repair(missing))
        else:
            inserted_ids = set(store.put_many_if_absent_atomic(missing))
        for child in missing:
            if child.job_id not in inserted_ids:
                continue
            _jobs_put(child.job_id, child)
    if dispatch:
        for child_id in parent.child_job_ids:
            child = cast(ScanJob | None, store.get(child_id, tenant_id=parent.tenant_id))
            if child is not None and child.status is JobStatus.PENDING:
                dispatch_scan_job(child)
    return parent


def dispatch_scan_job(job: ScanJob) -> None:
    """Dispatch an already-persisted scan through the configured durable queue."""

    store = _get_store()
    from agent_bom.api.scan_queue import claim_local_dispatch, distributed_scans_enabled, store_supports_dispatch

    if distributed_scans_enabled() and store_supports_dispatch(store):
        store.enqueue_for_dispatch(job)
    elif claim_local_dispatch(job):
        _submit_claimed(job)


def _submit_claimed(job: ScanJob) -> None:
    from agent_bom.api.scan_queue import release_local_dispatch

    try:
        submit_scan_job(job)
    except Exception:
        release_local_dispatch(job)
        raise


def _durably_pending(job: ScanJob) -> bool:
    store = _get_store()
    view = getattr(store, "get_status_view", None)
    if callable(view):
        row = view(job.job_id, job.tenant_id)
        return isinstance(row, dict) and row.get("status") == JobStatus.PENDING.value
    current = store.get(job.job_id, tenant_id=job.tenant_id)
    return current is not None and current.status is JobStatus.PENDING


def finish_local_scan_dispatch(job: ScanJob) -> None:
    """Release a finished worker's claim, re-running the job if it was dispatched meanwhile and is pending again.

    The durable row decides: a replay of the admission this worker just finished
    finds it terminal and is not run twice; a re-admission finds it pending.
    """

    from agent_bom.api.scan_queue import finish_local_dispatch, release_local_dispatch

    rerun = finish_local_dispatch(job)
    while rerun is not None:
        try:
            pending = run_tenant_bound(require_explicit_tenant_id(rerun.tenant_id), _durably_pending, rerun)
            if pending:
                _submit_claimed(rerun)
                return
        except Exception as exc:  # broad-except: the job stays durably pending for the next dispatch or reconciliation
            release_local_dispatch(rerun)
            _logger.warning("Re-dispatch of job=%s failed: %s", rerun.job_id, sanitize_text(sanitize_error(exc, generic=True)))
            return
        rerun = finish_local_dispatch(rerun)
