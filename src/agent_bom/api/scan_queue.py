"""Distributed scan dispatch — multi-replica work-stealing for scan jobs.

In a single-node deployment a scan runs on the node that received the request
(``submit_scan_job``). In a clustered control plane that pins scan throughput to
whichever replica got the HTTP call: an idle replica cannot help a busy one.

``DistributedScanWorker`` closes that gap. When enabled, scan jobs are enqueued
to a shared Postgres dispatch queue (``PostgresJobStore.enqueue_for_dispatch``)
and every replica runs a claim-loop that pulls the oldest claimable job via
``FOR UPDATE SKIP LOCKED`` and runs it on its own local worker pool. A job
submitted to a saturated node is therefore picked up by an idle one, and a job
whose owning node dies (lease expires) is reclaimed by another. Scan throughput
scales with replica count.

The queue holds only routing metadata; the scan payload and results stay in the
RLS-protected ``scan_jobs`` table and are loaded under the job's own tenant.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import uuid
from typing import TYPE_CHECKING, Any

from agent_bom.config import (
    API_SCAN_CLAIM_POLL_SECONDS,
    API_SCAN_LEASE_SECONDS,
    API_SCAN_WORKERS,
)
from agent_bom.core.settings import env_str
from agent_bom.security import sanitize_error, sanitize_text

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob

_logger = logging.getLogger(__name__)
_local_dispatch_lock = threading.Lock()
# Held claim per (tenant, job) -> the job of a dispatch refused while it was held, if any.
_local_dispatches: dict[tuple[str, str], ScanJob | None] = {}


def _dispatch_key(job: ScanJob) -> tuple[str, str]:
    return (job.tenant_id, job.job_id)


def claim_local_dispatch(job: ScanJob) -> bool:
    """Claim one in-process handoff; a fresh process may reclaim durable PENDING jobs.

    A refused claim is not dropped: it is recorded as a rerun request that the
    worker holding the claim acts on in :func:`finish_local_dispatch`, so a job
    re-admitted while its previous worker is still unwinding is not stranded.
    """

    key = _dispatch_key(job)
    with _local_dispatch_lock:
        if key in _local_dispatches:
            _local_dispatches[key] = job
            return False
        _local_dispatches[key] = None
        return True


def finish_local_dispatch(job: ScanJob) -> ScanJob | None:
    """End a worker's handoff; return a dispatch refused meanwhile, keeping the claim for it."""

    key = _dispatch_key(job)
    with _local_dispatch_lock:
        rerun = _local_dispatches.pop(key, None)
        if rerun is not None:
            _local_dispatches[key] = None
        return rerun


def release_local_dispatch(job: ScanJob) -> None:
    with _local_dispatch_lock:
        _local_dispatches.pop(_dispatch_key(job), None)


def reset_local_dispatches_for_tests() -> None:
    """Clear process-local handoffs between isolated test cases."""

    with _local_dispatch_lock:
        _local_dispatches.clear()


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "on", "yes", "enabled"}


def _falsy(value: str) -> bool:
    return value.strip().lower() in {"0", "false", "off", "no", "disabled"}


def distributed_scans_enabled() -> bool:
    """Whether scan jobs should be dispatched through the shared queue.

    Explicit ``AGENT_BOM_DISTRIBUTED_SCANS`` wins (on/off). Otherwise it defaults
    on exactly when the control plane is clustered (shared rate limit required or
    replicas > 1) and Postgres is configured — the same gate that makes other
    process-local control-plane state unsafe.
    """
    raw = os.environ.get("AGENT_BOM_DISTRIBUTED_SCANS", "")
    if raw and _falsy(raw):
        return False
    if not os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip():
        return False
    if raw and _truthy(raw):
        return True
    try:
        from agent_bom.api.storage.deployment import clustered_control_plane_required

        return clustered_control_plane_required()
    except Exception:  # noqa: BLE001
        return False


API_ROLES = frozenset({"all", "api", "worker"})


def api_role() -> str:
    """``AGENT_BOM_API_ROLE``: ``all`` (default), ``api`` (HTTP only) or ``worker`` (queue only)."""

    role = (env_str("AGENT_BOM_API_ROLE") or "all").strip().lower()
    if role not in API_ROLES:
        raise ValueError("AGENT_BOM_API_ROLE must be one of: all, api, worker")
    return role


def dispatch_worker_enabled(store: object) -> bool:
    """Whether this process runs the claim-loop that drains queued scans and pushes.

    An ``api`` replica only enqueues; a ``worker`` replica must have distributed
    dispatch or it would idle silently, so that misconfiguration fails startup.
    """

    role = api_role()
    if role == "api":
        return False
    enabled = distributed_scans_enabled() and store_supports_dispatch(store)
    if role == "worker" and not enabled:
        raise RuntimeError("AGENT_BOM_API_ROLE=worker requires distributed dispatch (Postgres and AGENT_BOM_DISTRIBUTED_SCANS)")
    return enabled


def store_supports_dispatch(store: object) -> bool:
    """True when the active job store exposes the dispatch-queue API."""
    return all(
        callable(getattr(store, name, None))
        for name in ("enqueue_for_dispatch", "claim_next", "renew_leases", "complete_dispatch", "requeue_expired_leases")
    )


class DistributedScanWorker:
    """Per-replica claim-loop that runs queued scan jobs on the local pool."""

    def __init__(
        self,
        store: Any,
        *,
        worker_id: str | None = None,
        lease_seconds: int = API_SCAN_LEASE_SECONDS,
        poll_seconds: int = API_SCAN_CLAIM_POLL_SECONDS,
        max_concurrent: int = API_SCAN_WORKERS,
    ) -> None:
        self._store = store
        self._worker_id = worker_id or f"{os.uname().nodename}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._lease = max(30, int(lease_seconds))
        self._poll = max(1, int(poll_seconds))
        self._max = max(1, int(max_concurrent))
        self._inflight: dict[tuple[str, str], str] = {}
        self._inflight_lock = threading.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        # Leases are renewed on their own thread so a slow claim loop or a busy
        # event loop never lets a live claim lapse into a peer's reclaim.
        self._beat_seconds = max(1.0, min(float(self._poll), self._lease / 6))
        self._beat_stop = threading.Event()
        self._beat_thread: threading.Thread | None = None

    @property
    def worker_id(self) -> str:
        return self._worker_id

    async def start(self) -> None:
        if self._task is None:
            self._stop.clear()
            self.start_heartbeat()
            self._task = asyncio.create_task(self._run(), name="distributed-scan-worker")
            _logger.info("Distributed scan worker started id=%s lease=%ss poll=%ss", self._worker_id, self._lease, self._poll)

    async def stop(self, *, keep_leases: bool = False) -> None:
        """Stop claiming; ``keep_leases`` renews in-flight claims until :meth:`stop_heartbeat` (shutdown drain)."""
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=self._poll + 5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None
        if not keep_leases:
            self.stop_heartbeat()

    def start_heartbeat(self) -> None:
        if self.heartbeat_alive():
            return
        self._beat_stop.clear()
        self._beat_thread = threading.Thread(target=self._heartbeat, name="distributed-scan-lease", daemon=True)
        self._beat_thread.start()

    def stop_heartbeat(self) -> None:
        self._beat_stop.set()
        if self._beat_thread is not None:
            self._beat_thread.join(timeout=self._beat_seconds + 5)
            self._beat_thread = None

    def heartbeat_alive(self) -> bool:
        return self._beat_thread is not None and self._beat_thread.is_alive()

    def _heartbeat(self) -> None:
        while not self._beat_stop.wait(self._beat_seconds):
            try:
                self._renew_inflight()
            except Exception as exc:  # broad-except: a missed beat is retried; only a long outage lets a lease lapse
                detail = sanitize_text(sanitize_error(exc, generic=True))
                _logger.warning("Dispatch lease renewal failed id=%s: %s", self._worker_id, detail)

    def _renew_inflight(self) -> None:
        with self._inflight_lock:
            claims = dict(self._inflight)
        if claims:
            self._store.renew_leases(claims, self._lease)

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self._tick)
            except Exception:  # noqa: BLE001
                _logger.error("Distributed scan worker tick failed id=%s", self._worker_id)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._poll)
            except asyncio.TimeoutError:
                pass  # the timeout only paces this loop

    def _tick(self) -> None:
        # Renew before reclaiming too, so this node never reclaims its own live work.
        self._renew_inflight()
        # End what cannot be redelivered, then reclaim jobs orphaned by dead
        # replicas (lease expired, status running, attempts left).
        from agent_bom.api.scan_job_reconciliation import fail_unrecoverable_dispatch_jobs

        fail_unrecoverable_dispatch_jobs(self._store)
        reclaimed = self._store.requeue_expired_leases()
        if reclaimed:
            _logger.info("Distributed scan worker reclaimed %d orphaned job(s)", reclaimed)
        # Claim up to local free capacity.
        from agent_bom.api.pipeline import submit_claimed_scan_job

        while not self._stop.is_set():
            with self._inflight_lock:
                if len(self._inflight) >= self._max:
                    break
            job = self._store.claim_next(self._worker_id, self._lease)
            if job is None:
                break
            claim_owner = job._dispatch_claim_owner
            if not claim_owner:
                _logger.error("Dispatch claim has no ownership token; refusing unfenced handoff job=%s", job.job_id)
                break
            key = (job.tenant_id, job.job_id)
            with self._inflight_lock:
                self._inflight[key] = claim_owner
            _logger.info("Claimed scan job=%s tenant=%s worker=%s", job.job_id, job.tenant_id, self._worker_id)
            try:
                submit_claimed_scan_job(
                    job,
                    lambda job_id, owner=claim_owner, tenant=job.tenant_id, abandoned=False: self._on_complete(
                        job_id, owner, tenant, abandoned=abandoned
                    ),
                )
            except Exception:  # noqa: BLE001
                # Could not hand off locally (e.g. executor draining): drop the
                # claim so another tick/replica can reclaim it after lease expiry.
                with self._inflight_lock:
                    if self._inflight.get(key) == claim_owner:
                        self._inflight.pop(key)
                _logger.error("Failed to submit claimed job=%s; will be reclaimed", job.job_id)
                break

    def _on_complete(self, job_id: str, claim_owner: str, tenant_id: str, *, abandoned: bool = False) -> None:
        key = (tenant_id, job_id)
        with self._inflight_lock:
            if self._inflight.get(key) == claim_owner:
                self._inflight.pop(key)
        if abandoned:
            # The run died before an outcome was durable. Heartbeats stop here, so
            # the lease expires and the job is redelivered, bounded by its attempts.
            _logger.warning("Claimed job=%s ended without an outcome; leaving it for redelivery", job_id)
            return
        try:
            self._store.complete_dispatch(job_id, tenant_id=tenant_id, claim_owner=claim_owner)
        except Exception:  # noqa: BLE001
            _logger.error("Failed to clear dispatch row job=%s", job_id)


async def start_dispatch_worker(store: Any) -> DistributedScanWorker | None:
    """Start this replica's claim-loop when its role and storage call for one.

    A misconfigured ``worker`` replica fails startup instead of idling; any other
    start failure degrades to single-node dispatch, as before.
    """
    if not dispatch_worker_enabled(store):
        return None
    worker = DistributedScanWorker(store)
    try:
        await worker.start()
    except Exception:  # noqa: BLE001
        _logger.error("Distributed scan worker failed to start; continuing single-node")
        return None
    return worker
