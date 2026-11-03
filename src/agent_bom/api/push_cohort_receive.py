"""Correlation-cohort child push ingest (``POST /v1/results/push`` with a cohort receipt).

Every blocking step (fingerprint, claim, store reads, normalization, the
fenced commit) runs in a worker thread so a large or contended cohort push
never stalls the event loop.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from fastapi import HTTPException

from agent_bom.api.correlation_cohort_ingest import (
    CorrelationCohortIngestError,
    cohort_evidence_created_at,
    commit_correlation_cohort_child,
    prior_or_conflict,
    validate_correlation_cohort_child,
)
from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyReservationHeartbeat,
    idempotency_owner_token,
    idempotency_request_fingerprint,
    idempotency_reservation_lease_seconds,
)
from agent_bom.api.models import JobStatus, PushPayload, ScanJob
from agent_bom.api.observability_events import _logger
from agent_bom.api.observability_push_receipts import _cohort_push_response, _release_cohort_push_claim, _wait_for_cohort_child
from agent_bom.api.push_evidence import audit_push_admission, normalize_pushed_report
from agent_bom.api.stores import _get_idempotency_store, _get_store
from agent_bom.security import sanitize_error, sanitize_text

_COHORT_ENDPOINT = "/v1/results/push/cohort"
_COHORT_ERROR_DETAILS = {
    "durable_store_required": "Correlation cohort ingest requires durable stores",
    "stale_evidence": "Correlation cohort evidence is stale",
    "duplicate_result": "Correlation cohort child already has a different result",
}


@dataclass
class _CohortPush:
    body: PushPayload
    source_id: str
    tenant_id: str
    child_id: str
    request_hash: str
    owner: str = field(default_factory=idempotency_owner_token)
    claimed: bool = False
    heartbeat: IdempotencyReservationHeartbeat | None = None

    async def claim(self) -> bool:
        try:
            _, self.claimed = await asyncio.to_thread(
                partial(
                    _get_idempotency_store().claim,
                    _COHORT_ENDPOINT,
                    self.tenant_id,
                    self.source_id,
                    self.child_id,
                    {"job_id": self.child_id, "committed": False},
                    request_hash=self.request_hash,
                    reservation_lease_seconds=idempotency_reservation_lease_seconds(),
                    owner_token=self.owner,
                )
            )
        except IdempotencyConflictError as exc:
            raise CorrelationCohortIngestError("duplicate_result") from exc
        if self.claimed:
            self.heartbeat = IdempotencyReservationHeartbeat(
                _get_idempotency_store(),
                _COHORT_ENDPOINT,
                self.tenant_id,
                self.source_id,
                self.child_id,
                request_hash=self.request_hash,
                owner_token=self.owner,
                lease_seconds=idempotency_reservation_lease_seconds(),
            )
            self.heartbeat.__enter__()
        return self.claimed

    def stop_heartbeat(self) -> None:
        if self.heartbeat is not None:
            self.heartbeat.ensure_owned()
            self.heartbeat.__exit__()
            self.heartbeat = None

    async def commit(self, action: Callable[[], tuple[ScanJob, ScanJob]]) -> dict:
        self.stop_heartbeat()
        child, parent = await asyncio.to_thread(
            _get_idempotency_store().commit_claim,
            _COHORT_ENDPOINT,
            self.tenant_id,
            self.source_id,
            self.child_id,
            {"job_id": self.child_id, "committed": True},
            action=action,
            request_hash=self.request_hash,
            owner_token=self.owner,
        )
        return _cohort_push_response(child, parent)

    async def release_unless_done(self) -> None:
        current = await asyncio.to_thread(_get_store().get, self.child_id, self.tenant_id)
        if self.claimed and (current is None or current.status is not JobStatus.DONE):
            _release_cohort_push_claim(
                tenant_id=self.tenant_id,
                source_id=self.source_id,
                child_id=self.child_id,
                request_hash=self.request_hash,
                owner_token=self.owner,
            )


def _cohort_report(body: PushPayload, child_id: str, max_age_hours: int) -> dict:
    report = normalize_pushed_report(body, fallback_scan_id=child_id)
    supplied_scan_id = str(report.get("scan_id") or "")
    if supplied_scan_id != child_id and "scan_id" in (body.model_extra or {}):
        raise CorrelationCohortIngestError("invalid_receipt")
    observed_at = next(
        (
            str(report.get(key) or "").strip()
            for key in ("observed_at", "scan_timestamp", "generated_at")
            if str(report.get(key) or "").strip()
        ),
        "",
    )
    report["observed_at"] = cohort_evidence_created_at([observed_at] if observed_at else [], max_age_hours=max_age_hours)
    report["scan_id"] = child_id
    report["pushed"] = True
    return report


def _cohort_http_error(exc: CorrelationCohortIngestError) -> HTTPException:
    if exc.code in {"observation_time_required", "invalid_observation_time"}:
        return HTTPException(status_code=422, detail="Correlation cohort evidence requires a valid observation time")
    return HTTPException(status_code=409, detail=_COHORT_ERROR_DETAILS.get(exc.code, "Correlation cohort receipt is invalid"))


async def _commit_cohort_child(push: _CohortPush, *, cohort_id: str, actor: str, persist_graph: Callable[..., Any]) -> dict:
    receipt = push.body.correlation_child_receipt
    if receipt is None:
        raise CorrelationCohortIngestError("invalid_receipt")
    context = await asyncio.to_thread(
        partial(
            validate_correlation_cohort_child,
            tenant_id=push.tenant_id,
            source_id=push.source_id,
            correlation_cohort_id=cohort_id,
            receipt=receipt,
            allowed_source_kinds={"ingest.result_push"},
        )
    )
    if not await push.claim():
        completed = await _wait_for_cohort_child(
            push.child_id, tenant_id=push.tenant_id, source_id=push.source_id, request_hash=push.request_hash
        )
        if completed is None:
            raise HTTPException(
                status_code=409,
                detail="An identical correlation cohort result is still being committed; retry shortly.",
                headers={"Retry-After": "1"},
            )
        return _cohort_push_response(*completed)
    current_child = await asyncio.to_thread(_get_store().get, push.child_id, push.tenant_id)
    if current_child is None:
        raise CorrelationCohortIngestError("invalid_receipt")
    context = type(context)(parent=context.parent, child=current_child)
    replay = prior_or_conflict(context.child, request_hash=push.request_hash)
    if replay is not None:
        parent = await asyncio.to_thread(_get_store().get, replay.parent_job_id or "", push.tenant_id)
        if parent is None:
            raise CorrelationCohortIngestError("invalid_receipt")
        return await push.commit(lambda: (replay, parent))
    report = await asyncio.to_thread(_cohort_report, push.body, context.child.job_id, receipt.max_age_hours)
    audit_push_admission(context.child, report, actor=actor, request_hash=push.request_hash)
    return await push.commit(
        lambda: commit_correlation_cohort_child(context, result=report, request_hash=push.request_hash, persist_graph=persist_graph)
    )


async def receive_cohort_push(body: PushPayload, *, tenant_id: str, cohort_id: str, actor: str, persist_graph: Callable[..., Any]) -> dict:
    """Commit one correlation-cohort child result under its idempotency fence."""

    cohort_receipt = body.correlation_child_receipt
    if cohort_receipt is None or not body.source_id:
        raise HTTPException(status_code=422, detail="Correlation cohort result requires source_id and a child receipt")
    request_hash = await asyncio.to_thread(idempotency_request_fingerprint, body)
    push = _CohortPush(body, body.source_id, tenant_id, cohort_receipt.child_job_id, request_hash)
    try:
        return await _commit_cohort_child(push, cohort_id=cohort_id, actor=actor, persist_graph=persist_graph)
    except CorrelationCohortIngestError as exc:
        await push.release_unless_done()
        raise _cohort_http_error(exc) from exc
    except HTTPException:
        await push.release_unless_done()
        raise
    except Exception as exc:  # noqa: BLE001
        await push.release_unless_done()
        _logger.error("Correlation cohort result commit failed: %s", sanitize_text(sanitize_error(exc, generic=True)))
        raise HTTPException(status_code=503, detail="Correlation cohort result could not be committed") from exc
    finally:
        if push.heartbeat is not None:
            push.heartbeat.__exit__()
