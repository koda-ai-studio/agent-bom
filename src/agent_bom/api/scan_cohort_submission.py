"""Immutable correlation-cohort admission and persistence."""

from __future__ import annotations

import contextlib
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, cast

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now
from agent_bom.api.scan_batches import refresh_batch_parent, scan_request_targets
from agent_bom.api.scan_cohorts import _CORRELATION_COHORT_NAMESPACE, correlation_cohort_parent_job_id
from agent_bom.api.scan_job_dispatch import dispatch_scan_job
from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active
from agent_bom.api.stores import _get_graph_store, _get_store, _jobs_put
from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard


def _cohort_manifest(
    source_requests: list[tuple[str, ScanRequest]],
    external_sources: list[tuple[str, str]] | None = None,
) -> tuple[list[tuple[str, ScanRequest | None, str]], str]:
    members: list[tuple[str, ScanRequest | None, str]] = [(source_id.strip(), request, "scan") for source_id, request in source_requests]
    members.extend((source_id.strip(), None, source_kind.strip()) for source_id, source_kind in (external_sources or []))
    normalized = sorted(members, key=lambda row: row[0])
    source_ids = [source_id for source_id, _request, _source_kind in normalized]
    if not 2 <= len(source_ids) <= 32:
        raise ValueError("a correlation cohort requires between 2 and 32 sources")
    if any(not source_id for source_id in source_ids) or len(set(source_ids)) != len(source_ids):
        raise ValueError("a correlation cohort requires distinct source ids")
    for source_id, request, source_kind in normalized:
        if request is not None and len(scan_request_targets(request)) != 1:
            raise ValueError(f"cohort source {source_id} must resolve to exactly one scan target")
        if request is None and source_kind not in {"ingest.result_push", "runtime.proxy", "runtime.gateway"}:
            raise ValueError(f"cohort source {source_id} has an unsupported external ingest kind")
    encoded = json.dumps(
        [
            {
                "source_id": source_id,
                "mode": "scan" if request is not None else "external_ingest",
                "source_kind": source_kind,
                "request": request.model_dump(mode="json", exclude_none=True) if request is not None else None,
            }
            for source_id, request, source_kind in normalized
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return normalized, hashlib.sha256(encoded).hexdigest()


def enqueue_correlation_cohort(
    *,
    tenant_id: str,
    triggered_by: str,
    correlation_cohort_id: str,  # noqa: F811 - parameter shadows the re-exported id helper
    source_requests: list[tuple[str, ScanRequest]],
    external_sources: list[tuple[str, str]] | None = None,
    max_age_hours: int,
    schedule_id: str | None = None,
    quota_guarded: bool = False,
    dispatch: bool = True,
) -> ScanJob:
    """Launch exact independent source scans as one immutable correlation cohort."""

    normalized_cohort_id = _validate_cohort_identity(correlation_cohort_id, max_age_hours)

    members, manifest_hash = _cohort_manifest(source_requests, external_sources)
    store = _get_store()
    parent_job_id = correlation_cohort_parent_job_id(
        tenant_id=tenant_id,
        correlation_cohort_id=normalized_cohort_id,
    )
    expected_child_ids = _cohort_child_ids(tenant_id, normalized_cohort_id, members)
    now = _now()
    child_jobs = _cohort_children(
        tenant_id,
        triggered_by,
        normalized_cohort_id,
        manifest_hash,
        max_age_hours,
        parent_job_id,
        members,
        expected_child_ids,
        now,
        schedule_id,
    )
    existing = cast(ScanJob | None, store.get(parent_job_id, tenant_id=tenant_id))
    if existing is not None:
        _repair_cohort_members(
            store,
            existing,
            tenant_id,
            normalized_cohort_id,
            manifest_hash,
            max_age_hours,
            parent_job_id,
            members,
            child_jobs,
            expected_child_ids,
            dispatch,
        )
        return existing

    parent = ScanJob(
        job_id=parent_job_id,
        tenant_id=tenant_id,
        batch_id=normalized_cohort_id,
        correlation_cohort_id=normalized_cohort_id,
        correlation_cohort_manifest_hash=manifest_hash,
        correlation_max_age_hours=max_age_hours,
        child_job_ids=[job.job_id for job in child_jobs],
        schedule_id=schedule_id,
        triggered_by=triggered_by,
        status=JobStatus.RUNNING,
        created_at=now,
        started_at=now,
        request=ScanRequest(),
        progress=[f"Correlation cohort created with {len(child_jobs)} independent source scan(s)"],
        target_count=len(child_jobs),
    )

    _initialize_cohort_policy(parent, store, max_age_hours)

    _persist_cohort(store, parent, child_jobs, tenant_id, quota_guarded, dispatch)
    return parent


def _cohort_children(
    tenant_id: str,
    triggered_by: str,
    normalized_cohort_id: str,
    manifest_hash: str,
    max_age_hours: int,
    parent_job_id: str,
    members: list[tuple[str, ScanRequest | None, str]],
    expected_child_ids: list[str],
    now: str,
    schedule_id: str | None,
) -> list[ScanJob]:
    """Materialize immutable source jobs in manifest order."""
    child_jobs: list[ScanJob] = []
    for index, ((source_id, request_body, source_kind), child_job_id) in enumerate(zip(members, expected_child_ids, strict=True), start=1):
        target = (
            scan_request_targets(request_body)[0] if request_body is not None else {"kind": "external_ingest", "source_kind": source_kind}
        )
        child_jobs.append(
            ScanJob(
                job_id=child_job_id,
                tenant_id=tenant_id,
                batch_id=normalized_cohort_id,
                correlation_cohort_id=normalized_cohort_id,
                correlation_cohort_manifest_hash=manifest_hash,
                correlation_max_age_hours=max_age_hours,
                parent_job_id=parent_job_id,
                target=target,
                target_index=index,
                target_count=len(members),
                source_id=source_id,
                schedule_id=schedule_id,
                triggered_by=triggered_by,
                created_at=now,
                request=request_body or ScanRequest(),
            )
        )
    return child_jobs


def _repair_cohort_members(
    store: Any,
    existing: ScanJob,
    tenant_id: str,
    normalized_cohort_id: str,
    manifest_hash: str,
    max_age_hours: int,
    parent_job_id: str,
    members: list[tuple[str, ScanRequest | None, str]],
    child_jobs: list[ScanJob],
    expected_child_ids: list[str],
    dispatch: bool,
) -> None:
    """Validate immutable inputs, repair missing children and resume dispatch."""
    if (
        existing.correlation_cohort_id != normalized_cohort_id
        or existing.correlation_cohort_manifest_hash != manifest_hash
        or existing.correlation_max_age_hours != max_age_hours
    ):
        raise ValueError("correlation cohort id was reused with different immutable inputs")
    if existing.child_job_ids != expected_child_ids:
        raise ValueError("persisted correlation cohort is incomplete")
    missing_children: list[ScanJob] = []
    for expected_child, (source_id, request_body, source_kind) in zip(child_jobs, members, strict=True):
        expected_child_id = expected_child.job_id
        child = cast(ScanJob | None, store.get(expected_child_id, tenant_id=tenant_id))
        expected_target = (
            scan_request_targets(request_body)[0] if request_body is not None else {"kind": "external_ingest", "source_kind": source_kind}
        )
        if child is None:
            missing_children.append(expected_child)
            continue
        if (
            child.parent_job_id != parent_job_id
            or child.source_id != source_id
            or child.correlation_cohort_id != normalized_cohort_id
            or child.correlation_cohort_manifest_hash != manifest_hash
            or child.correlation_max_age_hours != max_age_hours
            or child.target != expected_target
        ):
            raise ValueError("persisted correlation cohort is incomplete")
    if missing_children:
        atomic_repair = getattr(store, "put_many_if_absent_and_enqueue_atomic", None)
        from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch

        if dispatch and distributed_scans_enabled() and store_supports_dispatch(store) and callable(atomic_repair):
            inserted_ids = set(atomic_repair(missing_children))
        else:
            inserted_ids = set(store.put_many_if_absent_atomic(missing_children))
        for child in missing_children:
            if child.job_id not in inserted_ids:
                continue
            _jobs_put(child.job_id, child)
    if dispatch:
        for expected_child in child_jobs:
            child = cast(ScanJob | None, store.get(expected_child.job_id, tenant_id=tenant_id))
            if child is not None and child.status is JobStatus.PENDING and (child.target or {}).get("kind") != "external_ingest":
                dispatch_scan_job(child)


def _initialize_cohort_policy(parent: ScanJob, store: Any, max_age_hours: int) -> None:
    """Record the configured correlation policy on the new parent."""
    from agent_bom.api.auto_correlation import (
        AutoCorrelationPolicy,
        auto_correlation_backend_skip_reason,
        auto_correlation_policy_from_env,
        initial_auto_correlation_decision,
    )

    configured_policy = auto_correlation_policy_from_env()
    if configured_policy.enabled:
        cohort_policy = AutoCorrelationPolicy(
            enabled=True,
            max_age_hours=max_age_hours,
            max_batches_per_poll=configured_policy.max_batches_per_poll,
            max_active_per_tenant=configured_policy.max_active_per_tenant,
            poll_seconds=configured_policy.poll_seconds,
        )
        parent.result = {
            "auto_correlation": initial_auto_correlation_decision(
                parent,
                policy=cohort_policy,
                now=datetime.now(timezone.utc),
                backend_skip_reason=auto_correlation_backend_skip_reason(store, _get_graph_store()),
            )
        }


def _persist_cohort(store: Any, parent: ScanJob, child_jobs: list[ScanJob], tenant_id: str, quota_guarded: bool, dispatch: bool) -> None:
    """Admit and persist one cohort under the original tenant quota lock."""
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
    dispatchable_children = [child for child in child_jobs if (child.target or {}).get("kind") != "external_ingest"]
    with admission:
        atomic_handoff = getattr(store, "put_many_and_enqueue_atomic", None)
        from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch

        if dispatch and distributed_scans_enabled() and store_supports_dispatch(store) and callable(atomic_handoff):
            atomic_handoff([parent, *child_jobs], dispatchable_children)
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

    if dispatch:
        for child in dispatchable_children:
            dispatch_scan_job(child)


def _validate_cohort_identity(correlation_cohort_id: str, max_age_hours: int) -> str:
    """Validate canonical cohort identity and the immutable freshness bound."""
    try:
        normalized_cohort_id = str(uuid.UUID(correlation_cohort_id))
    except ValueError as exc:
        raise ValueError("correlation_cohort_id must be a UUID") from exc
    if normalized_cohort_id != correlation_cohort_id:
        raise ValueError("correlation_cohort_id must use canonical UUID form")
    if not 1 <= max_age_hours <= 8760:
        raise ValueError("correlation cohort max_age_hours must be between 1 and 8760")

    return normalized_cohort_id


def _cohort_child_ids(tenant_id: str, normalized_cohort_id: str, members: list[tuple[str, ScanRequest | None, str]]) -> list[str]:
    """Derive stable source identities in manifest order."""
    return [
        str(
            uuid.uuid5(
                _CORRELATION_COHORT_NAMESPACE,
                f"{tenant_id}\x00{normalized_cohort_id}\x00{source_id}",
            )
        )
        for source_id, _request, _source_kind in members
    ]
