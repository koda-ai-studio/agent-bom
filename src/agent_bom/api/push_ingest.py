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

import logging
import os
import threading
from types import TracebackType
from typing import Any
from uuid import uuid4

from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.push_evidence import audit_push_admission
from agent_bom.api.push_ingest_worker import INGEST_FAILED_DETAIL, _store_pushed_job
from agent_bom.api.scan_job_dispatch import dispatch_scan_job
from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch
from agent_bom.api.stores import _get_store
from agent_bom.api.tenant_quota import enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.config import API_SCAN_LEASE_SECONDS
from agent_bom.core.settings import env_str
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)
# The owner is one request heartbeating for itself, so a dead replica can be
# noticed sooner than a queue claim whose lease is sized for slow workers.
_REQUEST_LEASE_SECONDS = max(30, min(API_SCAN_LEASE_SECONDS, 120))
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


def _audit_view(job: ScanJob, job_result: dict) -> dict:
    """Admission audit fields; an admitted payload is normalized only later by the worker."""
    raw = job_result.get("payload")
    payload: dict = raw if isinstance(raw, dict) else job_result
    return {"scan_id": payload.get("scan_id") or job.job_id, "target_scope": payload.get("target_scope")}


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
        audit_push_admission(job, _audit_view(job, job_result), actor=actor, request_hash=request_hash)
        if distributed and callable(atomic_enqueue):
            atomic_enqueue([job], [job])
            return
        _store_pushed_job(store, job)
    dispatch_scan_job(job)


class RequestPushLease:
    """Lets a synchronous push be told apart from a dead one under distributed dispatch.

    The request thread owns the job and never enters the queue's claim loop. Its
    heartbeat is the liveness signal that lets a peer fail the job once the replica
    dies, and leaves a slow live push alone however old it is. The job stays failed
    rather than being replayed: an endpoint inventory is held only by the request.
    """

    def __init__(
        self, store: Any, job: ScanJob, *, lease_seconds: int = _REQUEST_LEASE_SECONDS, interval_seconds: float | None = None
    ) -> None:
        self._store = store
        self._job = job
        self._lease_seconds = lease_seconds
        self._interval = interval_seconds if interval_seconds is not None else lease_seconds / 3
        self._owner = f"push:{os.getpid()}:{uuid4().hex}"
        self._leased = (
            distributed_scans_enabled() and store_supports_dispatch(store) and callable(getattr(store, "put_with_request_lease", None))
        )
        self._stored = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> RequestPushLease:
        if self._leased:
            self._thread = threading.Thread(target=self._beat, name="push-request-lease", daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def _beat(self) -> None:
        key = (self._job.tenant_id, self._job.job_id)
        while not self._stop.wait(self._interval):
            if not self._stored:
                continue
            try:
                self._store.renew_leases({key: self._owner}, self._lease_seconds)
            except Exception as exc:  # broad-except: a missed beat is retried; only a long outage lets the lease lapse
                _logger.warning("Push lease renewal failed: %s", sanitize_text(sanitize_error(exc, generic=True)))

    def store_job(self) -> None:
        """Publish the job; the first write carries the lease so a crash cannot leave one without the other."""
        if self._leased and not self._stored:
            self._store.put_with_request_lease(self._job, self._owner, self._lease_seconds)
            self._stored = True
            return
        _store_pushed_job(self._store, self._job)

    def release(self) -> None:
        """The outcome is durable. A failed delete is harmless: the sweep clears the row of a finished job."""
        if not self._stored:
            return
        try:
            self._store.complete_dispatch(self._job.job_id, tenant_id=self._job.tenant_id, claim_owner=self._owner)
        except Exception as exc:  # broad-except: the outcome is already durable and must not be rolled back
            _logger.warning("Push lease release failed: %s", sanitize_text(sanitize_error(exc, generic=True)))


def redispatch_pending_push(job: ScanJob) -> None:
    """Re-offer a still-pending push; queue insert and local hand-off are idempotent."""

    if job.status is JobStatus.PENDING:
        dispatch_scan_job(job)
