"""Durable scan-job and batch admission."""

from __future__ import annotations

import contextlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now
from agent_bom.api.scan_batches import child_request_for_target, refresh_batch_parent, scan_request_targets
from agent_bom.api.scan_job_dispatch import dispatch_scan_job
from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active
from agent_bom.api.scan_request_context import _logger
from agent_bom.api.stores import _get_graph_store, _get_store, _jobs_put
from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.security import sanitize_error, sanitize_text


def enqueue_scan_job(
    *,
    tenant_id: str,
    triggered_by: str,
    request_body: ScanRequest,
    source_id: str | None = None,
    schedule_id: str | None = None,
    quota_guarded: bool = False,
    dispatch: bool = True,
    job_id: str | None = None,
) -> ScanJob:
    """Persist and optionally dispatch a scan job for async execution.

    ``quota_guarded`` is reserved for a caller already holding the tenant quota
    guard while it atomically admits an adjacent resource such as a trial scan
    credit and idempotency record.  It prevents a non-reentrant nested lock.
    """
    store = _get_store()
    targets = scan_request_targets(request_body)

    if len(targets) > 1:
        parent, child_jobs = _batch_jobs(tenant_id, triggered_by, request_body, targets, source_id, schedule_id, job_id)
        _initialize_batch_policy(parent, store)

        _persist_batch(store, parent, child_jobs, tenant_id, quota_guarded)

        for child in child_jobs:
            dispatch_scan_job(child)
        return parent

    job = ScanJob(
        job_id=job_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        source_id=source_id,
        schedule_id=schedule_id,
        triggered_by=triggered_by,
        created_at=_now(),
        request=request_body,
    )

    # Hold the per-tenant quota lock across the (check + insert) pair so two
    # concurrent requests serialise here and the second caller's check sees
    # the first caller's row. Without this, a tenant exceeds quota by N
    # under load (audit-4 P1).
    admission = (
        contextlib.nullcontext()
        if quota_guarded
        else tenant_quota_guard(
            tenant_id,
            lambda: enforce_active_scan_quota(tenant_id),
            lambda: enforce_retained_jobs_quota(tenant_id),
        )
    )
    with admission:
        store.put(job)
        _jobs_put(job.job_id, job)
        # Recompute after durable enqueue so the gauge survives missed
        # increments and reflects queued + running work from the store.
        try:
            reconcile_scan_jobs_active(store)
        except Exception:  # noqa: BLE001
            pass

    if not dispatch:
        return job
    _dispatch_admitted_job(job, store)
    return job


def _batch_jobs(
    tenant_id: str,
    triggered_by: str,
    request_body: ScanRequest,
    targets: list[dict[str, Any]],
    source_id: str | None,
    schedule_id: str | None,
    job_id: str | None,
) -> tuple[ScanJob, list[ScanJob]]:
    """Create deterministic child identities for one submitted batch."""
    batch_id = str(uuid.uuid4())
    now = _now()
    parent_job_id = job_id or str(uuid.uuid4())
    child_jobs: list[ScanJob] = []
    for index, target in enumerate(targets, start=1):
        child_jobs.append(
            ScanJob(
                job_id=str(uuid.uuid5(uuid.UUID(parent_job_id), f"{tenant_id}\x00{index}\x00{json.dumps(target, sort_keys=True)}")),
                tenant_id=tenant_id,
                batch_id=batch_id,
                parent_job_id=parent_job_id,
                target=target,
                target_index=index,
                target_count=len(targets),
                source_id=source_id,
                schedule_id=schedule_id,
                triggered_by=triggered_by,
                created_at=now,
                request=child_request_for_target(request_body, target),
            )
        )

    parent = ScanJob(
        job_id=parent_job_id,
        tenant_id=tenant_id,
        batch_id=batch_id,
        child_job_ids=[job.job_id for job in child_jobs],
        source_id=source_id,
        schedule_id=schedule_id,
        triggered_by=triggered_by,
        status=JobStatus.RUNNING,
        created_at=now,
        started_at=now,
        request=request_body,
        progress=[f"Batch scan created with {len(child_jobs)} target job(s)"],
        target_count=len(targets),
    )
    return parent, child_jobs


def _initialize_batch_policy(parent: ScanJob, store: Any) -> None:
    """Attach the currently configured automatic correlation decision."""
    from agent_bom.api.auto_correlation import (
        auto_correlation_backend_skip_reason,
        auto_correlation_policy_from_env,
        initial_auto_correlation_decision,
    )

    auto_correlation_policy = auto_correlation_policy_from_env()
    if auto_correlation_policy.enabled:
        backend_skip_reason = auto_correlation_backend_skip_reason(store, _get_graph_store())
        parent.result = {
            "auto_correlation": initial_auto_correlation_decision(
                parent,
                policy=auto_correlation_policy,
                now=datetime.now(timezone.utc),
                backend_skip_reason=backend_skip_reason,
            )
        }


def _persist_batch(store: Any, parent: ScanJob, child_jobs: list[ScanJob], tenant_id: str, quota_guarded: bool) -> None:
    """Commit parent and children with the original atomic queue handoff."""
    attempted_jobs = len(child_jobs) + 1
    admission = (
        contextlib.nullcontext()
        if quota_guarded
        else tenant_quota_guard(
            tenant_id,
            lambda: enforce_active_scan_quota(tenant_id, attempted=attempted_jobs),
            lambda: enforce_retained_jobs_quota(tenant_id, attempted=attempted_jobs),
        )
    )
    with admission:
        atomic_handoff = getattr(store, "put_many_and_enqueue_atomic", None)
        from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch

        if distributed_scans_enabled() and store_supports_dispatch(store) and callable(atomic_handoff):
            atomic_handoff([parent, *child_jobs], child_jobs)
        else:
            store.put_many_atomic([parent, *child_jobs])
        _jobs_put(parent.job_id, parent)
        for child in child_jobs:
            _jobs_put(child.job_id, child)
        try:
            refresh_batch_parent(parent.job_id, tenant_id=tenant_id)
        except Exception:  # noqa: BLE001
            pass
        try:
            reconcile_scan_jobs_active(store)
        except Exception:  # noqa: BLE001
            pass


def _dispatch_admitted_job(job: ScanJob, store: Any) -> None:
    """Persist a failed handoff so admitted jobs cannot remain orphaned pending."""
    try:
        dispatch_scan_job(job)
    except Exception as exc:  # noqa: BLE001 - local/shared dispatch boundary
        # The job row already exists. Never leave it looking claimable when the
        # handoff failed, because an HTTP retry could otherwise create a second
        # job while this orphan remains permanently pending.
        job.status = JobStatus.FAILED
        job.completed_at = _now()
        job.error = "Scan dispatch failed before execution."
        job.progress.append("Dispatch failed before execution")
        try:
            store.put(job)
        except Exception as persist_exc:  # noqa: BLE001
            _logger.error(
                "Failed to persist scan dispatch failure job=%s: %s",
                job.job_id,
                sanitize_text(sanitize_error(persist_exc, generic=True)),
            )
        _jobs_put(job.job_id, job, compact_terminal=True)
        try:
            reconcile_scan_jobs_active(store)
        except Exception:  # noqa: BLE001
            pass
        _logger.error(
            "Scan dispatch failed job=%s: %s",
            job.job_id,
            sanitize_text(sanitize_error(exc, generic=True)),
        )
        raise RuntimeError("Scan dispatch failed before execution.") from None
