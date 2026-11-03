"""Worker half of pushed-result ingest: persist an admitted push off the request path.

The scan executor and the distributed claim-loop both hand a claimed job to
``_run_scan_sync``; a job that carries an admitted push report is routed here
instead of the scan pipeline. The graph persistence call is the same one the
synchronous push path makes, only invoked from the worker.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from agent_bom.api.graph_persistence import persist_graph_snapshot
from agent_bom.api.hub_ingest import ingest_runtime_findings
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.observability_events import _logger, _now
from agent_bom.api.pipeline import register_push_ingest_handler
from agent_bom.api.stores import _get_graph_store, _get_store
from agent_bom.api.trend_comparison import push_scope_id
from agent_bom.api.trend_recording import record_scan_trend_best_effort
from agent_bom.security import sanitize_error, sanitize_text

INGEST_FAILED_DETAIL = "Pushed result could not be committed"
_ACTIVE = frozenset({JobStatus.PENDING, JobStatus.RUNNING})
# Post-commit hooks (exec read prewarm) registered by the API layer; kept as a
# registry so this worker module never imports the route graph.
_COMMIT_LISTENERS: list[Callable[[str], object]] = []


def register_push_commit_listener(listener: Callable[[str], object]) -> None:
    if listener not in _COMMIT_LISTENERS:
        _COMMIT_LISTENERS.append(listener)


def notify_push_committed(tenant_id: str) -> None:
    """Run post-commit hooks (exec read warm-up); a hook never fails a committed push."""
    for listener in list(_COMMIT_LISTENERS):
        try:
            listener(tenant_id)
        except Exception as exc:  # noqa: BLE001  # broad-except: a warm-up hook must never fail a committed ingest
            _logger.warning("Push commit listener failed: %s", sanitize_text(sanitize_error(exc, generic=True)))


def is_push_ingest_job(job: ScanJob) -> bool:
    """A queued push carries its admitted report; a queued scan has no result yet."""

    return job.status in _ACTIVE and isinstance(job.result, dict) and job.result.get("pushed") is True


def _store_pushed_job(store: Any, job: ScanJob) -> None:
    """Publish detached evidence before graph enrichment can mutate the writer's report.

    SQL stores serialize on put. The ephemeral store retains references, so it
    needs its own snapshot to keep concurrent current-estate readers stable.
    """
    stored = job.model_copy(deep=True) if getattr(store, "retains_job_objects_in_memory", False) else job
    store.put(stored)


def _graph_snapshot_exists(tenant_id: str, scan_id: str) -> bool:
    """Return whether a snapshot for ``scan_id`` is already persisted.

    Fails safe: when the backend cannot answer, report ``True`` so a later
    rollback leaves the snapshot alone rather than risk deleting data this
    push did not write.
    """
    try:
        _resolved, generation = _get_graph_store().snapshot_identity(tenant_id=tenant_id, scan_id=scan_id)
    except Exception as exc:  # noqa: BLE001 - unknown backend state must never authorize a delete
        _logger.warning("Graph snapshot pre-check unavailable: %s", sanitize_text(sanitize_error(exc, generic=True)))
        return True
    return bool(generation)


def _record_push_trend(job: ScanJob, job_result: dict, *, source_id: str | None, target_scope: Any) -> None:
    """Record the posture trend point once the pushed job is durable (best effort)."""
    record_scan_trend_best_effort(
        job_result,
        tenant_id=job.tenant_id,
        scan_id=job.job_id,
        completed_at=job.completed_at,
        scope_id=push_scope_id(source_id, target_scope),
        headline_posture=True,
    )


def _persist_push_graph(job: ScanJob, report: dict, *, write_generation: str) -> None:
    persist_graph_snapshot(
        job, report, store_factory=_get_graph_store, write_generation=write_generation, finding_sink=ingest_runtime_findings
    )


def _record_ingest_failure(store: Any, job: ScanJob, result: dict, *, graph_scan_id: str, generation: str, preexisted: bool) -> None:
    if not preexisted:
        try:
            _get_graph_store().delete_snapshot(tenant_id=job.tenant_id, scan_id=graph_scan_id, expected_generation=generation)
        except Exception as exc:  # noqa: BLE001  # broad-except: rollback is best effort; the failure is recorded on the job
            _logger.error("Graph rollback failed: %s", sanitize_text(sanitize_error(exc, generic=True)))
    result.pop("graph_persistence", None)
    job.status = JobStatus.FAILED
    job.completed_at = _now()
    job.error = INGEST_FAILED_DETAIL
    job.progress.append("Ingest failed; retry the push with the same idempotency key")
    store.put(job)


def run_push_ingest(job: ScanJob) -> None:
    """Persist one admitted push: graph projection, then the terminal job row.

    Re-reads the durable row first so a redelivered or reclaimed dispatch never
    re-runs an ingest another worker already finished.
    """

    store = _get_store()
    current = store.get(job.job_id, tenant_id=job.tenant_id)
    if current is None or not is_push_ingest_job(current):
        return
    result: dict = current.result if isinstance(current.result, dict) else {}
    graph_scan_id = str(result.get("scan_id") or current.job_id)
    preexisted = _graph_snapshot_exists(current.tenant_id, graph_scan_id)
    generation = uuid.uuid4().hex
    try:
        _persist_push_graph(current, result, write_generation=generation)
        current.status = JobStatus.DONE
        current.completed_at = _now()
        current.progress.append("Ingest committed")
        _store_pushed_job(store, current)
    except Exception as exc:  # noqa: BLE001  # broad-except: the job row records the failure and the client retries by key
        _logger.error("Asynchronous push ingest failed: %s", sanitize_text(sanitize_error(exc, generic=True)))
        _record_ingest_failure(store, current, result, graph_scan_id=graph_scan_id, generation=generation, preexisted=preexisted)
        return
    _record_push_trend(current, result, source_id=current.source_id, target_scope=result.get("target_scope"))
    notify_push_committed(current.tenant_id)


register_push_ingest_handler(run_push_ingest)
