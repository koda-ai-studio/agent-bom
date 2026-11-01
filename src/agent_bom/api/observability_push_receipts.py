"""Idempotency, graph persistence and receipt helpers for pushed scans."""

from __future__ import annotations

import asyncio
from typing import Any, cast

from agent_bom.api.correlation_cohort_ingest import CorrelationCohortIngestError, prior_or_conflict
from agent_bom.api.exec_read_prewarm import schedule_exec_prewarm
from agent_bom.api.models import JobStatus, PushPayload, ScanJob
from agent_bom.api.observability_events import _logger
from agent_bom.api.stores import _get_fleet_store, _get_graph_store, _get_idempotency_store, _get_store
from agent_bom.api.trend_comparison import push_scope_id
from agent_bom.api.trend_recording import record_scan_trend_best_effort
from agent_bom.security import sanitize_error, sanitize_text


def _store_pushed_job(store: Any, job: ScanJob) -> None:
    """Publish detached evidence before graph enrichment can mutate the writer's report.

    SQL stores serialize on put. The ephemeral store retains references, so it
    needs its own snapshot to keep concurrent current-estate readers stable.
    """
    stored = job.model_copy(deep=True) if getattr(store, "retains_job_objects_in_memory", False) else job
    store.put(stored)


def _prepare_push_endpoint(body: PushPayload, job: ScanJob, job_result: dict, tenant_id: str) -> tuple:
    fleet_store = _get_fleet_store()
    previous_endpoint = None
    endpoint = None
    if body.source_id and body.endpoint_inventory:
        from agent_bom.api.fleet_store import endpoint_inventory_evidence, endpoint_summary_from_inventory

        previous_endpoint = fleet_store.get_endpoint(body.source_id, tenant_id=tenant_id)
        endpoint = endpoint_summary_from_inventory(
            endpoint_id=body.source_id,
            tenant_id=tenant_id,
            inventory=body.endpoint_inventory,
            scan_id=str(job_result.get("scan_id") or job.job_id),
            observed_at=str(job_result.get("observed_at") or job_result.get("scan_timestamp") or job.created_at),
        )
        # Store and graph only the bounded evidence summary. Raw process,
        # application, service, listener, container, and image rows remain
        # on the source endpoint and never enter the control-plane job.
        job_result["endpoint_inventory"] = endpoint_inventory_evidence(endpoint)
    return fleet_store, previous_endpoint, endpoint


def _graph_snapshot_exists(tenant_id: str, scan_id: str) -> bool:
    """Return whether a snapshot for ``scan_id`` is already persisted.

    Fails safe: when the backend cannot answer, report ``True`` so a later
    rollback leaves the snapshot alone rather than risk deleting data this
    push did not write.
    """
    try:
        _resolved, generation = _get_graph_store().snapshot_identity(tenant_id=tenant_id, scan_id=scan_id)
    except Exception as exc:  # noqa: BLE001 — unknown must never authorize a delete
        _logger.warning("Graph snapshot pre-check unavailable: %s", sanitize_text(sanitize_error(exc, generic=True)))
        return True
    return bool(generation)


def _release_push_idempotency_claim(
    store: Any,
    *,
    tenant_id: str,
    source_id: str,
    idempotency_key: str,
    request_hash: str,
    owner_token: str = "",
) -> None:
    try:
        store.release(
            "/v1/results/push",
            tenant_id,
            source_id,
            idempotency_key,
            request_hash=request_hash,
            owner_token=owner_token,
        )
    except Exception as exc:  # noqa: BLE001
        _logger.error("Push idempotency rollback failed: %s", sanitize_text(sanitize_error(exc, generic=True)))


def _record_push_trend(job: ScanJob, job_result: dict, body: PushPayload) -> None:
    """Record the posture trend point once the pushed job is durable (best effort)."""
    record_scan_trend_best_effort(
        job_result,
        tenant_id=job.tenant_id,
        scan_id=job.job_id,
        completed_at=job.completed_at,
        scope_id=push_scope_id(body.source_id, body.target_scope),
        headline_posture=True,
    )


def _pushed_job_receipt(job: ScanJob, *, prewarm_tenant: str | None = None) -> dict[str, Any]:
    """The push receipt; a newly committed push also warms the exec reads off the request path."""
    if prewarm_tenant:
        schedule_exec_prewarm(prewarm_tenant)
    result = job.result if isinstance(job.result, dict) else {}
    raw_scan_run = result.get("scan_run")
    scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
    return {
        "job_id": job.job_id,
        "source_id": job.source_id or "",
        "status": "stored",
        "scan_outcome": str(scan_run.get("outcome") or "failed"),
        "target_scope": result.get("target_scope"),
        "replacement_scope_status": result.get("replacement_scope_status", "unscoped"),
        "graph_persistence": _public_graph_receipt(result),
    }


def _public_graph_receipt(result: dict) -> dict[str, Any]:
    """Return bounded durable graph facts, excluding arbitrary stored details."""
    graph = result.get("graph_persistence")
    if not isinstance(graph, dict) or graph.get("status") != "persisted":
        return {"status": "unknown"}
    receipt: dict[str, Any] = {"status": "persisted"}
    scan_id = graph.get("scan_id")
    if isinstance(scan_id, str) and scan_id:
        receipt["scan_id"] = sanitize_text(scan_id, max_len=200)
    for key in ("nodes", "edges"):
        value = graph.get(key)
        if type(value) is int and value >= 0:
            receipt[key] = value
    return receipt


def _pushed_job_has_persisted_graph(job: ScanJob) -> bool:
    """Return whether the durable job records a completed graph projection."""

    result = job.result if isinstance(job.result, dict) else {}
    graph_persistence = result.get("graph_persistence")
    return isinstance(graph_persistence, dict) and graph_persistence.get("status") == "persisted"


async def _wait_for_pushed_job(
    job_id: str,
    *,
    tenant_id: str,
    idempotency_source: str,
    idempotency_key: str,
    request_hash: str,
) -> ScanJob | None:
    """Bounded wait for the reservation owner to finish the durable commit."""
    if not job_id:
        return None
    for _attempt in range(100):
        receipt = await asyncio.to_thread(
            _get_idempotency_store().get,
            "/v1/results/push",
            tenant_id,
            idempotency_source,
            idempotency_key,
            request_hash=request_hash,
        )
        job = await asyncio.to_thread(_get_store().get, job_id, tenant_id)
        if job is not None and receipt is not None and receipt.get("committed") is True:
            # The owner publishes this receipt only after its held-claim action
            # commits every durable projection. The receipt is therefore the
            # cross-replica completion fence; requiring an additional mutable
            # marker here can incorrectly reject a successfully committed
            # request when a backend does not project that marker into the job.
            return cast(ScanJob, job)
        await asyncio.sleep(0.01)
    return None


async def _wait_for_cohort_child(
    child_id: str,
    *,
    tenant_id: str,
    source_id: str,
    request_hash: str,
) -> tuple[ScanJob, ScanJob] | None:
    """Wait briefly for the distributed cohort-child reservation owner."""

    for _attempt in range(100):
        receipt = await asyncio.to_thread(
            _get_idempotency_store().get,
            "/v1/results/push/cohort",
            tenant_id,
            source_id,
            child_id,
            request_hash=request_hash,
        )
        child = await asyncio.to_thread(_get_store().get, child_id, tenant_id)
        if child is not None and child.status is JobStatus.DONE:
            replay = prior_or_conflict(child, request_hash=request_hash)
            if replay is None:
                raise CorrelationCohortIngestError("invalid_receipt")
            parent = await asyncio.to_thread(_get_store().get, replay.parent_job_id or "", tenant_id)
            if parent is None:
                raise CorrelationCohortIngestError("invalid_receipt")
            if receipt is not None and receipt.get("committed") is True:
                return replay, parent
        await asyncio.sleep(0.01)
    return None


def _release_cohort_push_claim(*, tenant_id: str, source_id: str, child_id: str, request_hash: str, owner_token: str = "") -> None:
    try:
        _get_idempotency_store().release(
            "/v1/results/push/cohort",
            tenant_id,
            source_id,
            child_id,
            request_hash=request_hash,
            owner_token=owner_token,
        )
    except Exception as exc:  # noqa: BLE001
        _logger.error("Cohort push idempotency rollback failed: %s", sanitize_text(sanitize_error(exc, generic=True)))


def _cohort_push_response(child: ScanJob, parent: ScanJob) -> dict[str, Any]:
    result = child.result if isinstance(child.result, dict) else {}
    raw_scan_run = result.get("scan_run")
    scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
    auto_correlation = (parent.result or {}).get("auto_correlation") if isinstance(parent.result, dict) else None
    return {
        "job_id": child.job_id,
        "source_id": child.source_id or "",
        "status": "stored",
        "scan_outcome": str(scan_run.get("outcome") or "complete"),
        "correlation_cohort_id": child.correlation_cohort_id or "",
        "cohort_manifest_hash": child.correlation_cohort_manifest_hash or "",
        "parent_job_id": parent.job_id,
        "auto_correlation": auto_correlation if isinstance(auto_correlation, dict) else None,
    }
