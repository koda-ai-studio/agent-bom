"""Asynchronous pushed-result ingest: admit on the request, persist on a worker.

``POST /v1/results/push`` with ``Prefer: respond-async`` (or with
``AGENT_BOM_PUSH_INGEST_MODE=async``) validates the report, writes the job row
once as ``pending`` and hands it to the same durable dispatch scans use: the
shared Postgres ``scan_dispatch_queue`` (``FOR UPDATE SKIP LOCKED`` + lease)
when distributed dispatch is on, otherwise the local scan executor. The worker
(:mod:`agent_bom.api.push_ingest_worker`) persists the graph and flips the job
to ``done`` or ``failed``. The idempotency key is the dedupe fence: the job id
is derived from it, so a retry addresses the same job instead of a duplicate.
"""

from __future__ import annotations

from typing import Any

from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.push_evidence import audit_push_admission
from agent_bom.api.push_ingest_worker import INGEST_FAILED_DETAIL, _store_pushed_job
from agent_bom.api.scan_job_dispatch import dispatch_scan_job
from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch
from agent_bom.api.stores import _get_store
from agent_bom.api.tenant_quota import enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.core.settings import env_str

PUSH_ENDPOINT = "/v1/results/push"
PUSH_INGEST_MODE_ENV = "AGENT_BOM_PUSH_INGEST_MODE"
#: Seconds a client should wait before polling an accepted push again.
PUSH_RETRY_AFTER_SECONDS = 2


def push_ingest_mode(prefer_header: str | None) -> str:
    """Return ``async`` or ``sync`` for one push request.

    ``auto`` (default) honours RFC 7240 ``Prefer: respond-async`` so clients
    that predate asynchronous ingest keep their synchronous 201 receipt.
    """

    configured = (env_str(PUSH_INGEST_MODE_ENV) or "auto").strip().lower()
    if configured in {"sync", "async"}:
        return configured
    tokens = {token.strip().split("=", 1)[0].lower() for token in (prefer_header or "").split(",")}
    return "async" if "respond-async" in tokens else "sync"


def push_status_url(job_id: str) -> str:
    return f"{PUSH_ENDPOINT}/{job_id}"


def accepted_push_receipt(job_id: str, *, source_id: str, ingest: str = "queued") -> dict[str, Any]:
    """Receipt for a push that is durable but not yet projected into the graph."""

    return {
        "job_id": job_id,
        "source_id": source_id,
        "status": "accepted",
        "ingest": ingest,
        "status_url": push_status_url(job_id),
    }


def failed_push_receipt(job_id: str, *, source_id: str) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "source_id": source_id,
        "status": "failed",
        "ingest": "failed",
        "detail": INGEST_FAILED_DETAIL,
        "status_url": push_status_url(job_id),
    }


def admit_pushed_job(job: ScanJob, job_result: dict, *, actor: str, request_hash: str) -> None:
    """Write the admitted report once, as ``pending``, and dispatch it.

    Runs in a worker thread. Quota admission and the audit record precede the
    durable write exactly as on the synchronous path. A retry of a ``failed``
    ingest re-admits the same deterministic job id.
    """

    job.status = JobStatus.PENDING
    job.completed_at = None
    job.error = None
    job.result = job_result
    job.progress.append("Queued for asynchronous ingest")
    store = _get_store()
    atomic_enqueue = getattr(store, "put_many_and_enqueue_atomic", None)
    distributed = distributed_scans_enabled() and store_supports_dispatch(store) and callable(atomic_enqueue)
    with tenant_quota_guard(job.tenant_id, lambda: enforce_retained_jobs_quota(job.tenant_id)):
        audit_push_admission(job, job_result, actor=actor, request_hash=request_hash)
        if distributed and callable(atomic_enqueue):
            atomic_enqueue([job], [job])
            return
        _store_pushed_job(store, job)
    dispatch_scan_job(job)


def redispatch_pending_push(job: ScanJob) -> None:
    """Re-offer a still-pending push; queue insert and local hand-off are idempotent."""

    if job.status is JobStatus.PENDING:
        dispatch_scan_job(job)
