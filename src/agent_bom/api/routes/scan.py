"""Scan submission, status, findings, inventory, exports and auxiliary scanner routes."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timezone
from functools import partial
from typing import Annotated, Any, Literal, NamedTuple, cast

import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response

from agent_bom.api import compliance_hub_store, finding_cursor, findings_count_cache, findings_current, job_status_count_cache, time_window
from agent_bom.api.ai_scan_runtime import (  # noqa: F401 - re-exported route-module API
    _ai_scan_call,
    _dataclass_to_dict,
)
from agent_bom.api.bulk_findings_ingest import (  # noqa: F401 - re-exported route-module API
    _BULK_FINDINGS_MAX_ITEMS,
    _BULK_FINDINGS_SOURCE_MAX_LENGTH,
    BulkFindingsRequest,
    PackageCheckRequest,
    _coerce_bulk_cvss,
    _coerce_bulk_severity,
    _derive_bulk_finding_id,
    _normalized_bulk_finding,
)
from agent_bom.api.finding_facets import _FACET_DEADLINE_SECONDS as _FACET_DEADLINE_SECONDS
from agent_bom.api.finding_facets import _FACET_SCAN_BUDGET as _FACET_SCAN_BUDGET
from agent_bom.api.finding_facets import _FACET_SEVERITY_BANDS as _FACET_SEVERITY_BANDS
from agent_bom.api.finding_facets import _TRIAGE_DISPOSITIONS as _TRIAGE_DISPOSITIONS
from agent_bom.api.finding_facets import _count_facet_row as _count_facet_row
from agent_bom.api.finding_facets import _facet_completeness as _facet_completeness
from agent_bom.api.finding_facets import _facet_exploit_bucket as _facet_exploit_bucket
from agent_bom.api.finding_facets import _facet_has_fix as _facet_has_fix
from agent_bom.api.finding_facets import _facet_reachability_bucket as _facet_reachability_bucket
from agent_bom.api.finding_facets import _facet_severity_histogram as _facet_severity_histogram
from agent_bom.api.finding_facets import _FacetCounts as _FacetCounts
from agent_bom.api.finding_facets import _FacetScopes as _FacetScopes
from agent_bom.api.finding_facets import _finding_facets as _finding_facets
from agent_bom.api.finding_facets import _finding_facets_bounded as _finding_facets_bounded
from agent_bom.api.finding_facets import _walk_facet_rows as _walk_facet_rows
from agent_bom.api.finding_grouping import _attach_grouping_metadata as _attach_grouping_metadata
from agent_bom.api.finding_grouping import _collect_group_occurrences as _collect_group_occurrences
from agent_bom.api.finding_grouping import _finding_group_identity as _finding_group_identity
from agent_bom.api.finding_grouping import _finding_group_offset as _finding_group_offset
from agent_bom.api.finding_grouping import _group_occurrence_rows as _group_occurrence_rows
from agent_bom.api.finding_grouping import _grouped_severity_counts as _grouped_severity_counts
from agent_bom.api.finding_grouping import _groups_envelope as _groups_envelope
from agent_bom.api.finding_grouping import attach_lane_counts, select_group_lane
from agent_bom.api.finding_list_envelope import HUB_LIST_OFFSET_CEILING as _HUB_LIST_OFFSET_CEILING
from agent_bom.api.finding_list_envelope import finding_list_envelope
from agent_bom.api.finding_list_helpers import (  # noqa: F401 - re-exported route-module API
    _ALLOWED_FINDING_SEVERITIES,
    _ALLOWED_FINDING_SORTS,
    _ALLOWED_FINDING_STATUSES,
    _DEFAULT_FINDING_STATUS,
    _FACET_LITERAL_SEVERITY_BANDS,
    _FACET_PAYLOAD_SCOPE_KEYS,
    _FINDING_GROUP_MAX_OCCURRENCES,
    _FINDING_GROUP_OCCURRENCE_SAMPLE,
    _FRESHNESS_BUCKETS,
    _finding_occurrence_summary,
    _freshness_bucket,
    _normalize_facet_severity,
    _normalize_finding_sort,
    _serialize_finding_group,
)
from agent_bom.api.finding_list_projection import FindingListInclude, finding_list_projection, list_include_or_422, project_list_row
from agent_bom.api.finding_merge import _BULK_MERGE_CHUNK as _BULK_MERGE_CHUNK
from agent_bom.api.finding_merge import MergedScanBulkPage as MergedScanBulkPage
from agent_bom.api.finding_merge import _merge_bulk_kwargs as _merge_bulk_kwargs
from agent_bom.api.finding_merge import _merged_scan_bulk_page as _merged_scan_bulk_page
from agent_bom.api.finding_merge import _resolve_bulk_findings_total as _resolve_bulk_findings_total
from agent_bom.api.finding_merge import _ScanBulkMerge as _ScanBulkMerge
from agent_bom.api.finding_reachability import project_persisted_graph_reachability
from agent_bom.api.finding_read_context import finding_read_snapshot, read_once
from agent_bom.api.finding_row_shapes import (  # noqa: F401 - re-exported route-module API
    _EMPTY_FIELD_VALUES,
    _SUPPLEMENTARY_BACKFILL_FIELDS,
    _backfill_supplementary_fields,
    _finding_key,
    _iter_package_findings,
    _normalize_finding_identifiers,
    _package_base_name,
    _package_identity,
    _row_vuln_id,
    _scan_source_labels,
)
from agent_bom.api.finding_scope_filters import _canonical_group_key as _canonical_group_key
from agent_bom.api.finding_scope_filters import _canonical_scope_filters as _canonical_scope_filters
from agent_bom.api.finding_scope_filters import _finding_identity as _finding_identity
from agent_bom.api.finding_scope_filters import _finding_list_filters as _finding_list_filters
from agent_bom.api.finding_scope_filters import _finding_sort_key as _finding_sort_key
from agent_bom.api.finding_scope_filters import _row_asset_key as _row_asset_key
from agent_bom.api.finding_scope_filters import _row_matches_scope as _row_matches_scope
from agent_bom.api.finding_snapshot_metadata import snapshot_envelope
from agent_bom.api.finding_suppression import project_current_suppressions
from agent_bom.api.finding_view_filters import _FINDINGS_VIEW_FILTER_MAX_ROWS as _FINDINGS_VIEW_FILTER_MAX_ROWS
from agent_bom.api.finding_view_filters import _copy_first_page_metadata as _copy_first_page_metadata
from agent_bom.api.finding_view_filters import _finding_triage_state as _finding_triage_state
from agent_bom.api.finding_view_filters import _matches_reachability as _matches_reachability
from agent_bom.api.finding_view_filters import _view_envelope as _view_envelope
from agent_bom.api.finding_view_filters import _view_filtered_row as _view_filtered_row
from agent_bom.api.finding_view_filters import _view_filters as _view_filters
from agent_bom.api.finding_view_filters import _ViewWalk as _ViewWalk
from agent_bom.api.finding_view_filters import _walk_view_filtered_findings as _walk_view_filtered_findings
from agent_bom.api.findings_current import _finding_snapshot_jobs, current_scan_jobs
from agent_bom.api.hub_ingest import hub_ingest_store_writes, hub_store_call
from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyReservationHeartbeat,
    deterministic_batch_id,
    idempotency_owner_token,
    idempotency_request_fingerprint,
    idempotency_reservation_lease_seconds,
)
from agent_bom.api.models import (
    InventoryResponse,
    JobStatus,
    ScanJob,
    ScanRequest,
)
from agent_bom.api.pipeline import _now, request_scan_cancellation, submit_scan_job
from agent_bom.api.read_models import FindingsResponse, JobsResponse, documented
from agent_bom.api.read_models.scan import ScanDriversResponse, ScanLicensesResponse, ScanStatusResponse, ScanVexResponse
from agent_bom.api.remediation_view import CurrentRemediationResponse
from agent_bom.api.scan_batches import child_request_for_target, refresh_batch_parent, scan_request_targets
from agent_bom.api.scan_cohorts import (  # noqa: F401 - re-exported route-module API
    _CORRELATION_COHORT_NAMESPACE,
    correlation_cohort_id,
    correlation_cohort_parent_job_id,
)
from agent_bom.api.scan_finding_projection import _finding_from_blast_radius as _finding_from_blast_radius
from agent_bom.api.scan_finding_projection import _iter_scan_findings as _iter_scan_findings
from agent_bom.api.scan_finding_projection import _project_finding_owners_and_suppressions as _project_finding_owners_and_suppressions
from agent_bom.api.scan_finding_read import _bulk_ingested_findings_for_tenant as _bulk_ingested_findings_for_tenant
from agent_bom.api.scan_finding_read import _cached_scan_findings as _cached_scan_findings
from agent_bom.api.scan_finding_read import _completed_jobs_for_tenant as _completed_jobs_for_tenant
from agent_bom.api.scan_finding_read import _current_scan_rows as _current_scan_rows
from agent_bom.api.scan_finding_read import current_open_scan_findings as current_open_scan_findings
from agent_bom.api.scan_finding_read import iter_tenant_scan_spine_findings as iter_tenant_scan_spine_findings
from agent_bom.api.scan_finding_read import persisted_finding_evidence as persisted_finding_evidence
from agent_bom.api.scan_graph_view import _attach_unified_graph_view as _attach_unified_graph_view
from agent_bom.api.scan_graph_view import _context_graph_payload as _context_graph_payload
from agent_bom.api.scan_graph_view import _effective_reach_lookup as _effective_reach_lookup
from agent_bom.api.scan_graph_view import _graph_export_response as _graph_export_response
from agent_bom.api.scan_graph_view import _scan_graph_compute_call as _scan_graph_compute_call
from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active
from agent_bom.api.scan_job_views import (  # noqa: F401 - re-exported route-module API
    _inventory_packages_from_agents,
    _job_response_payload,
    _job_summary_payload,
    _redact_scan_result_for_response,
)
from agent_bom.api.scan_path_jail import (  # noqa: F401 - re-exported route-module API
    _LOCAL_SCAN_DISABLE_VALUES,
    _api_local_scans_enabled,
    _api_scan_path_or_400,
    _api_scan_root,
    _enforce_api_scan_path_owner,
    _sanitize_api_path,
)
from agent_bom.api.stores import (
    _get_graph_store,
    _get_idempotency_store,
    _get_store,
    _job_lock,
    _jobs_get,
    _jobs_is_compacted,
    _jobs_pop,
    _jobs_put,
)
from agent_bom.api.tenancy import require_body_tenant_match, require_request_tenant_id
from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.evidence.agent_bom import AgentBomDocument
from agent_bom.evidence.scan_agent_bom import AgentSelectionError, build_scan_agent_bom
from agent_bom.finding_scope import (
    FindingClass,
    canonical_finding_severity_filter,
)
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()

_logger = logging.getLogger(__name__)


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _require_json_content_type(request: Request) -> None:
    """Reject ambiguous bulk-ingest bodies before accepting caller data."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json" and not media_type.endswith("+json"):
        raise HTTPException(status_code=422, detail="Content-Type must be application/json")


# Shared off-loop hub ingest write path (also used by /v1/compliance/ingest).
# Aliased here so existing references / monkeypatch targets keep working.
_hub_store_call = hub_store_call
_bulk_ingest_store_writes = hub_ingest_store_writes


# Local-path fields on a ScanRequest that must be confined to the API scan jail
# before the job is queued. Non-path targets (images, connectors, repo_url, k8s)
# are intentionally excluded.
_SCAN_LOCAL_PATH_SINGLE_FIELDS = ("inventory", "gha_path", "sbom", "external_scan", "vex")
_SCAN_LOCAL_PATH_LIST_FIELDS = ("tf_dirs", "agent_projects", "jupyter_dirs", "filesystem_paths")


def _sanitize_scan_request_paths(body: ScanRequest, *, tenant_id: str = "") -> ScanRequest:
    """Confine every local-path field on a scan request to the API scan jail.

    The primary ``POST /v1/scan`` flow historically ran only
    :func:`agent_bom.security.validate_path` on these fields, which rejects
    ``..`` traversal but accepts absolute paths and does not confine them to a
    configured root — letting an authenticated caller read arbitrary host files
    (e.g. ``{"inventory": "/etc/hosts"}``). Route each populated field through the
    same :func:`_api_scan_path_or_400` helper and ``_api_local_scans_enabled``
    gate the dedicated scan endpoints use, so the default posture rejects
    local-path scans consistently on the primary endpoint too. ``external_scan``
    and ``vex`` are included here even though they were opened unvalidated.
    """
    if body.discover_host:
        from agent_bom.api.scan_boundary import require_host_discovery_for_tenant
        from agent_bom.security import SecurityError

        try:
            require_host_discovery_for_tenant(tenant_id)
        except SecurityError as exc:
            raise HTTPException(status_code=403, detail="Host discovery is not enabled for this tenant") from exc
    updates: dict[str, Any] = {}
    for field in _SCAN_LOCAL_PATH_SINGLE_FIELDS:
        value = getattr(body, field)
        if value:
            updates[field] = _api_scan_path_or_400(value)
    for field in _SCAN_LOCAL_PATH_LIST_FIELDS:
        values = getattr(body, field)
        if values:
            updates[field] = [_api_scan_path_or_400(entry) for entry in values]
    if not updates:
        return body
    return body.model_copy(update=updates)


def _request_header(request: Request, key: str) -> str:
    headers = getattr(request, "headers", None)
    if headers is None:
        return ""
    return str(headers.get(key, "") or "")


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _triggered_by(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "api"


def _visible_to_tenant(job: ScanJob, tenant_id: str) -> bool:
    return getattr(job, "tenant_id", "default") == tenant_id


def _redact_finding_page(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from agent_bom.finding_scope import safe_finding_response_payload

    return [safe_finding_response_payload(project_list_row(row)) for row in rows]


def _job_for_request(request: Request, job_id: str) -> ScanJob:
    tenant_id = _tenant_id(request)
    in_mem = _jobs_get(job_id, tenant_id=tenant_id)
    if in_mem is not None and _visible_to_tenant(in_mem, tenant_id):
        if _jobs_is_compacted(in_mem):
            persisted = _get_store().get(job_id, tenant_id=tenant_id)
            if persisted is not None:
                if persisted.child_job_ids:
                    refreshed = refresh_batch_parent(persisted.job_id, tenant_id=tenant_id)
                    return refreshed or persisted
                return cast(ScanJob, persisted)
        if in_mem.child_job_ids:
            refreshed = refresh_batch_parent(in_mem.job_id, tenant_id=tenant_id)
            return refreshed or in_mem
        return in_mem
    job = _get_store().get(job_id, tenant_id=tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.child_job_ids:
        refreshed = refresh_batch_parent(job.job_id, tenant_id=tenant_id)
        return refreshed or job
    return cast(ScanJob, job)


async def _load_job_for_request(request: Request, job_id: str) -> ScanJob:
    """Hydrate one job off-loop because durable stores use synchronous I/O."""
    return cast(
        ScanJob,
        await anyio.to_thread.run_sync(partial(_job_for_request, request, job_id)),
    )


async def _job_response_payload_off_loop(job: ScanJob) -> ScanJob:
    """Sanitize a potentially large full result in the bounded worker pool."""
    return cast(
        ScanJob,
        await anyio.to_thread.run_sync(partial(_job_response_payload, job)),
    )


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

    try:
        normalized_cohort_id = str(uuid.UUID(correlation_cohort_id))
    except ValueError as exc:
        raise ValueError("correlation_cohort_id must be a UUID") from exc
    if normalized_cohort_id != correlation_cohort_id:
        raise ValueError("correlation_cohort_id must use canonical UUID form")
    if not 1 <= max_age_hours <= 8760:
        raise ValueError("correlation cohort max_age_hours must be between 1 and 8760")

    members, manifest_hash = _cohort_manifest(source_requests, external_sources)
    store = _get_store()
    parent_job_id = correlation_cohort_parent_job_id(
        tenant_id=tenant_id,
        correlation_cohort_id=normalized_cohort_id,
    )
    expected_child_ids = [
        str(
            uuid.uuid5(
                _CORRELATION_COHORT_NAMESPACE,
                f"{tenant_id}\x00{normalized_cohort_id}\x00{source_id}",
            )
        )
        for source_id, _request, _source_kind in members
    ]
    now = _now()
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
    existing = cast(ScanJob | None, store.get(parent_job_id, tenant_id=tenant_id))
    if existing is not None:
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
                scan_request_targets(request_body)[0]
                if request_body is not None
                else {"kind": "external_ingest", "source_kind": source_kind}
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
    return parent


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
    return job


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
    from agent_bom.api.scan_queue import (
        claim_local_dispatch,
        distributed_scans_enabled,
        release_local_dispatch,
        store_supports_dispatch,
    )

    if distributed_scans_enabled() and store_supports_dispatch(store):
        store.enqueue_for_dispatch(job)
    else:
        if not claim_local_dispatch(job.job_id):
            return
        try:
            submit_scan_job(job)
        except Exception:
            release_local_dispatch(job.job_id)
            raise


# ─── Core Scan Endpoints ─────────────────────────────────────────────────────


@router.post("/scan", response_model=ScanJob, status_code=202, tags=["scan"])
async def create_scan(request: Request, body: ScanRequest) -> ScanJob:
    """Start a scan. Returns immediately with a job_id.
    Poll GET /v1/scan/{job_id} for results, or stream via /v1/scan/{job_id}/stream.

    ``format`` selects the shape of the completed result. ``json`` (the default)
    leaves the AI-BOM JSON in ``result``; ``cyclonedx``, ``sarif``, ``spdx``,
    ``html``, and ``text`` render that report into ``result_document``, which is
    what the CLI and MCP surfaces emit for the same value.

    Retry-safe: repeating the request with the same ``Idempotency-Key`` header
    returns the first job instead of minting a new job_id per attempt; reusing
    the key with a different body is a 409 conflict.
    """
    tenant_id = _tenant_id(request)
    # Confine local-path targets to the API scan jail before any queueing or
    # idempotency work — the same gate/helper the dedicated scan endpoints use.
    body = _sanitize_scan_request_paths(body, tenant_id=tenant_id)
    idem_key = _request_header(request, "Idempotency-Key")
    idem_source = _request_header(request, "X-Agent-Bom-Source-Id") or "scan"
    request_hash = idempotency_request_fingerprint(body)
    idem_store = _get_idempotency_store()
    claimed = False
    owner_token = idempotency_owner_token()
    heartbeat: IdempotencyReservationHeartbeat | None = None
    reserved_job_id = ""
    if idem_key:
        reserved_job_id = deterministic_batch_id(f"/v1/scan:{tenant_id}:{idem_source}:{idem_key}:{request_hash}")
        try:
            cached, claimed = idem_store.claim(
                "/v1/scan",
                tenant_id,
                idem_source,
                idem_key,
                {"job_id": reserved_job_id, "committed": False},
                request_hash=request_hash,
                reservation_lease_seconds=idempotency_reservation_lease_seconds(),
                owner_token=owner_token,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
        if not claimed:
            cached_job_id = str(cached.get("job_id") or "")
            existing = await _wait_for_idempotent_job(
                cached_job_id,
                tenant_id=tenant_id,
                idempotency_store=idem_store,
                endpoint="/v1/scan",
                source_id=idem_source,
                idempotency_key=idem_key,
                request_hash=request_hash,
            )
            if existing is not None:
                existing = await asyncio.to_thread(_repair_scan_batch, existing)
                return _job_response_payload(existing)
            raise HTTPException(
                status_code=409,
                detail="An identical scan request is still being committed; retry shortly.",
                headers={"Retry-After": "1"},
            )
        heartbeat = IdempotencyReservationHeartbeat(
            idem_store,
            "/v1/scan",
            tenant_id,
            idem_source,
            idem_key,
            request_hash=request_hash,
            owner_token=owner_token,
            lease_seconds=idempotency_reservation_lease_seconds(),
        )
        heartbeat.__enter__()
        cached_job_id = str(cached.get("job_id") or reserved_job_id)
        existing = await asyncio.to_thread(_get_store().get, cached_job_id, tenant_id)
        if existing is not None:
            heartbeat.ensure_owned()
            heartbeat.__exit__()
            heartbeat = None
            recovered = cast(
                ScanJob,
                await asyncio.to_thread(
                    idem_store.commit_claim,
                    "/v1/scan",
                    tenant_id,
                    idem_source,
                    idem_key,
                    {"job_id": existing.job_id, "committed": True},
                    action=lambda: _repair_scan_batch(existing),
                    request_hash=request_hash,
                    owner_token=owner_token,
                ),
            )
            return _job_response_payload(recovered)

    try:
        if claimed:
            if heartbeat is not None:
                heartbeat.ensure_owned()
                heartbeat.__exit__()
                heartbeat = None
            job = cast(
                ScanJob,
                await asyncio.to_thread(
                    idem_store.commit_claim,
                    "/v1/scan",
                    tenant_id,
                    idem_source,
                    idem_key,
                    {"job_id": reserved_job_id, "committed": True},
                    action=lambda: enqueue_scan_job(
                        tenant_id=tenant_id,
                        triggered_by=_triggered_by(request),
                        request_body=body,
                        job_id=reserved_job_id,
                    ),
                    request_hash=request_hash,
                    owner_token=owner_token,
                ),
            )
        else:
            job = enqueue_scan_job(
                tenant_id=tenant_id,
                triggered_by=_triggered_by(request),
                request_body=body,
            )
    except Exception:
        durable_job_exists = True
        if claimed:
            try:
                durable_job_exists = _get_store().get(reserved_job_id, tenant_id=tenant_id) is not None
            except Exception as lookup_exc:  # noqa: BLE001
                _logger.error(
                    "Scan commit-state lookup failed: %s",
                    sanitize_text(sanitize_error(lookup_exc, generic=True)),
                )
        if claimed and not durable_job_exists:
            _release_scan_idempotency_claim(
                idem_store,
                tenant_id=tenant_id,
                source_id=idem_source,
                idempotency_key=idem_key,
                request_hash=request_hash,
                owner_token=owner_token,
            )
        raise
    finally:
        if heartbeat is not None:
            heartbeat.__exit__()
    return job


def _release_scan_idempotency_claim(
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
            "/v1/scan",
            tenant_id,
            source_id,
            idempotency_key,
            request_hash=request_hash,
            owner_token=owner_token,
        )
    except Exception as exc:  # noqa: BLE001
        _logger.error("Scan idempotency rollback failed: %s", sanitize_text(sanitize_error(exc, generic=True)))


async def _wait_for_idempotent_job(
    job_id: str,
    *,
    tenant_id: str,
    idempotency_store: Any,
    endpoint: str,
    source_id: str,
    idempotency_key: str,
    request_hash: str,
) -> ScanJob | None:
    """Wait until the reservation owner publishes both its receipt and job."""
    if not job_id:
        return None
    for _attempt in range(100):
        receipt = await asyncio.to_thread(
            idempotency_store.get,
            endpoint,
            tenant_id,
            source_id,
            idempotency_key,
            request_hash=request_hash,
        )
        if receipt is None or receipt.get("committed") is not True:
            await asyncio.sleep(0.01)
            continue
        existing = _jobs_get(job_id, tenant_id=tenant_id)
        if existing is None:
            existing = await asyncio.to_thread(_get_store().get, job_id, tenant_id)
        if existing is not None:
            return existing
        await asyncio.sleep(0.01)
    return None


@router.post("/scan/check", tags=["scan"])
async def check_package(body: PackageCheckRequest) -> dict[str, Any]:
    """Check one package with the same vulnerability intelligence as MCP."""

    from mcp.server.mcpserver.exceptions import ToolError

    from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
    from agent_bom.mcp_server_runtime import validate_ecosystem
    from agent_bom.mcp_tools.scanning import check_impl

    try:
        result = await check_impl(
            package=body.package,
            ecosystem=body.ecosystem,
            version=body.version,
            offline=body.offline,
            _validate_ecosystem=lambda value: validate_ecosystem(value, SUPPORTED_PACKAGE_ECOSYSTEM_SET),
            _truncate_response=lambda value: value,
        )
    except ToolError as exc:
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc

    payload = json.loads(result)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Package check returned an invalid response")
    return payload


@router.get("/scan/drivers", **documented(ScanDriversResponse), tags=["scan"])
def list_scan_drivers(include_planned: bool = True) -> dict:
    """List scanner driver contracts and orchestration semantics."""

    from agent_bom.scanners.registry import (
        list_registered_scanners,
        scanner_registry_summary,
        scanner_registry_warnings,
    )

    return {
        "drivers": [registration.to_dict() for registration in list_registered_scanners(include_planned=include_planned)],
        "summary": scanner_registry_summary(),
        "warnings": scanner_registry_warnings(),
    }


@router.get("/scan/{job_id}", response_model=ScanJob, tags=["scan"])
async def get_scan(request: Request, job_id: str) -> ScanJob:
    """Fetch scan status and full results.

    ``result`` is always the canonical AI-BOM JSON. When the request asked for a
    non-json ``format``, ``result_document`` carries that rendering and
    ``result_format`` names it.
    """
    return await _job_response_payload_off_loop(await _load_job_for_request(request, job_id))


@router.get("/scan/{job_id}/status", **documented(ScanStatusResponse), tags=["scan"])
async def get_scan_status(request: Request, job_id: str) -> dict[str, Any]:
    """Poll lightweight scan status without serializing large result payloads."""
    return _job_summary_payload(await _load_job_for_request(request, job_id))


@router.get("/scan/{job_id}/attack-flow", tags=["scan"])
async def get_attack_flow(
    request: Request,
    job_id: str,
    cve: str | None = None,
    severity: str | None = None,
    framework: str | None = None,
    agent: str | None = None,
) -> dict:
    """Get the attack flow graph for a completed scan.

    Returns React Flow-compatible nodes/edges showing the CVE -> package ->
    server -> agent attack chain with credential and tool branches.

    Query params for filtering:
      ?cve=CVE-2025-xxx     - show only this CVE's blast radius
      ?severity=critical     - filter by severity level
      ?framework=LLM03       - filter by OWASP/ATLAS/NIST tag
      ?agent=claude-desktop  - filter to a specific agent
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    from agent_bom.output.attack_flow import build_attack_flow

    blast_radius = job.result.get("blast_radius", [])
    agents_data = job.result.get("agents", [])

    payload = build_attack_flow(
        blast_radius,
        agents_data,
        cve=cve,
        severity=severity,
        framework=framework,
        agent_name=agent,
    )
    from agent_bom.output.interop_security import sanitize_linked_document

    return sanitize_linked_document(payload)


@router.get("/scan/{job_id}/context-graph", tags=["scan"])
async def get_context_graph(request: Request, job_id: str, agent: str | None = None) -> dict:
    """Get the agent context graph with lateral movement analysis.

    Returns nodes, edges, lateral paths, interaction risks, and stats for
    a completed scan.  Optionally filter lateral paths to a single agent.

    Query params:
      ?agent=claude-desktop  - only compute lateral paths from this agent
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    tenant_id = str(getattr(request.state, "tenant_id", "") or "")
    return cast(
        dict,
        await _scan_graph_compute_call(_context_graph_payload, job.result, agent=agent, scan_id=job.job_id, tenant_id=tenant_id),
    )


@router.get("/scan/{job_id}/graph-export", tags=["scan"], response_model=None)
async def get_graph_export(
    request: Request,
    job_id: str,
    format: str = "json",
    mermaid_limit: Annotated[
        int,
        Query(
            ge=0,
            le=5000,
            description="Maximum nodes rendered for Mermaid output; 0 renders the full graph.",
        ),
    ] = 80,
) -> dict | str | PlainTextResponse:
    """Export the dependency graph in graph-native formats.

    Query params:
      ?format=json      JSON nodes/edges (default)
      ?format=dot       Graphviz DOT
      ?format=mermaid   Mermaid flowchart
      ?format=graphml   GraphML with AIBOM attributes (yEd/Gephi/NetworkX)
      ?format=cypher    Neo4j Cypher import script
      ?mermaid_limit=80 Maximum nodes rendered for Mermaid; 0 renders all
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    result = job.result if isinstance(job.result, dict) else {}
    return cast(
        "dict | str | PlainTextResponse",
        await _scan_graph_compute_call(
            _graph_export_response,
            result,
            format=format,
            mermaid_limit=mermaid_limit,
            scan_id=job.job_id,
            tenant_id=_tenant_id(request),
        ),
    )


@router.get(
    "/scan/{job_id}/agent-bom",
    tags=["scan"],
    response_model=AgentBomDocument,
    dependencies=[cast(Any, require_authenticated_permission("read"))],
)
async def get_scan_agent_bom(
    request: Request,
    job_id: str,
    agent_id: Annotated[str, Query(min_length=1, max_length=512)],
) -> AgentBomDocument:
    """Export one exact recorded agent's composition with its source-scan receipt.

    Inherits authenticated scan-read tenancy. Explicit local no-auth mode is
    the existing development exception. Labels never resolve identity; missing
    or conflicting identity fails closed. No discovery or provider calls run.
    Findings and runtime/authority assessments remain separate scan evidence.
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not isinstance(job.result, dict):
        raise HTTPException(status_code=409, detail="A completed scan result is required")
    try:
        return cast(
            AgentBomDocument,
            await _scan_graph_compute_call(
                build_scan_agent_bom,
                job.result,
                agent_id=agent_id,
                tenant_id=require_request_tenant_id(request),
                scan_id=job.job_id,
            ),
        )
    except AgentSelectionError as exc:
        raise HTTPException(status_code=409, detail="Agent identity is unavailable or ambiguous in this scan") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Scan composition is invalid, unsupported, or exceeds export limits") from exc


@router.get("/findings/remediation", tags=["scan"], response_model=CurrentRemediationResponse)
async def get_current_remediation(request: Request) -> CurrentRemediationResponse:
    """Package upgrade actions from the tenant's current findings across targets."""
    from agent_bom.api.remediation_view import current_remediation_response, remediation_finding_projection

    snapshot = await asyncio.to_thread(
        current_findings_snapshot,
        request,
        max_findings=10_000,
        window_days=0,
        project_graph_reachability=False,
        row_projection=remediation_finding_projection,
    )
    return current_remediation_response(snapshot)


@router.get("/scan/{job_id}/remediation", tags=["scan"])
async def get_remediation_plan(request: Request, job_id: str) -> dict:
    """Return package upgrade actions without transferring the full scan report.

    One entry per package, with an explicit total for the client.
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")
    plan = job.result.get("remediation_plan") or [] if isinstance(job.result, dict) else []
    return {"job_id": job_id, "remediation_plan": plan, "total": len(plan)}


@router.get("/scan/{job_id}/licenses", **documented(ScanLicensesResponse), tags=["scan"])
async def get_licenses(request: Request, job_id: str) -> dict:
    """Return a completed scan's license findings, coverage, status and categories."""
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # If the scan already computed license_report, return it
    if isinstance(job.result, dict) and job.result.get("license_report"):
        return cast(dict, job.result["license_report"])

    # Otherwise compute on-the-fly from scan result agents
    from agent_bom.license_policy import evaluate_license_policy as _eval_lic
    from agent_bom.license_policy import to_serializable as _lic_ser
    from agent_bom.models import Agent as _AgentModel
    from agent_bom.models import AgentType as _AgentType
    from agent_bom.models import MCPServer as _ServerModel
    from agent_bom.models import Package as _PkgModel

    agents_data = job.result.get("agents", []) if isinstance(job.result, dict) else []
    model_agents = []
    for ad in agents_data:
        servers = []
        for sd in ad.get("mcp_servers", []):
            pkgs = [
                _PkgModel(
                    name=p.get("name", ""),
                    version=p.get("version", ""),
                    ecosystem=p.get("ecosystem", ""),
                    license=p.get("license"),
                    license_expression=p.get("license_expression"),
                )
                for p in sd.get("packages", [])
            ]
            servers.append(_ServerModel(name=sd.get("name", ""), command=sd.get("command", ""), packages=pkgs))
        model_agents.append(
            _AgentModel(name=ad.get("name", ""), agent_type=_AgentType(ad.get("type", "custom")), config_path="", mcp_servers=servers)
        )

    lic_report = _eval_lic(model_agents)
    return dict(_lic_ser(lic_report))


@router.get("/scan/{job_id}/vex", **documented(ScanVexResponse), tags=["scan"])
async def get_vex(request: Request, job_id: str) -> dict:
    """Get the VEX (Vulnerability Exploitability eXchange) document for a completed scan.

    Returns VEX statements with vulnerability status (affected, not_affected,
    fixed, under_investigation), justifications, and statistics.
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # Return pre-computed VEX data if available
    if isinstance(job.result, dict) and job.result.get("vex"):
        return cast(dict, job.result["vex"])

    # Otherwise generate on-the-fly from blast_radii
    return {"statements": [], "stats": {"total_statements": 0, "affected": 0, "not_affected": 0, "fixed": 0, "under_investigation": 0}}


@router.get("/scan/{job_id}/skill-audit", tags=["scan"])
async def get_skill_audit(request: Request, job_id: str) -> dict:
    """Get the skill security audit results for a completed scan.

    Returns findings from the skill file security audit including
    typosquat detection, unverified servers, shell access, and more.
    Empty results if no skill files were scanned.
    """
    job = await _load_job_for_request(request, job_id)

    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    return cast(
        dict,
        job.result.get(
            "skill_audit",
            {
                "findings": [],
                "packages_checked": 0,
                "servers_checked": 0,
                "credentials_checked": 0,
                "passed": True,
            },
        ),
    )


@router.post("/scan/{job_id}/cancel", response_model=ScanJob, tags=["scan"])
async def cancel_scan(request: Request, job_id: str) -> ScanJob:
    """Request cooperative cancellation of a pending or running scan job.

    Sets ``JobStatus.CANCELLED``; the worker exits at the next pipeline
    checkpoint. Terminal jobs are returned unchanged. Use ``DELETE`` to discard
    the job record after cancellation (or for already-finished jobs).
    """
    job = await _load_job_for_request(request, job_id)
    await anyio.to_thread.run_sync(partial(request_scan_cancellation, job))
    return _job_response_payload(await _load_job_for_request(request, job_id))


@router.delete("/scan/{job_id}", status_code=204, tags=["scan"])
async def delete_scan(request: Request, job_id: str) -> None:
    """Discard a job record.

    For pending/running jobs, requests cooperative cancellation first so the
    worker does not finish into a resurrected DONE state after discard.
    """
    job = await _load_job_for_request(request, job_id)
    if job.status in {JobStatus.PENDING, JobStatus.RUNNING}:
        await anyio.to_thread.run_sync(partial(request_scan_cancellation, job))
    in_memory = _jobs_pop(job_id, tenant_id=job.tenant_id) if _visible_to_tenant(job, _tenant_id(request)) else None
    in_store = await anyio.to_thread.run_sync(partial(_get_store().delete, job_id, tenant_id=_tenant_id(request)))
    if not in_memory and not in_store:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@router.get("/scan/{job_id}/stream", tags=["scan"])
async def stream_scan(request: Request, job_id: str) -> Response:
    """Server-Sent Events stream for real-time scan progress.

    Connect with EventSource:
        const es = new EventSource('/v1/scan/{job_id}/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    try:
        from agent_bom.api.sse_authorization import AuthorizedEventSourceResponse as EventSourceResponse
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail="SSE requires sse-starlette. Install: pip install 'agent-bom[api]'",
        ) from exc

    await _load_job_for_request(request, job_id)
    tenant_id = _tenant_id(request)

    import json as _json

    async def event_generator() -> AsyncIterator[dict[str, Any]]:
        sent = 0
        lock = _job_lock(job_id)
        start = time.monotonic()
        while time.monotonic() - start < 2100:  # 35 min max (exceeds stuck-job timeout)
            current = _jobs_get(job_id, tenant_id=tenant_id)
            if current is None:
                break
            if not _visible_to_tenant(current, tenant_id):
                break
            # Thread-safe snapshot of new progress lines and status
            with lock:
                new_lines = list(current.progress[sent:])
                status = current.status
            from agent_bom.security import sanitize_sensitive_payload

            for line in new_lines:
                try:
                    parsed = _json.loads(line)
                    if isinstance(parsed, dict) and parsed.get("type") == "step":
                        parsed = sanitize_sensitive_payload(parsed)
                        yield {"data": _json.dumps(parsed)}
                    else:
                        yield {"data": _json.dumps({"type": "progress", "message": sanitize_sensitive_payload(line)})}
                except (_json.JSONDecodeError, ValueError):
                    yield {"data": _json.dumps({"type": "progress", "message": sanitize_sensitive_payload(line)})}
                sent += 1
            if status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                yield {"data": _json.dumps({"type": "done", "status": status, "job_id": job_id})}
                break
            await asyncio.sleep(0.25)

    return cast(Response, EventSourceResponse(event_generator()))


@router.get("/jobs", **documented(JobsResponse), tags=["scan"])
async def list_jobs(
    request: Request,
    # enforce limit/offset caps via Pydantic so callers
    # cannot pass `?limit=10000` to fan out the in-memory scan-job list.
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    include_details: bool = False,
    q: Annotated[str | None, Query(max_length=200)] = None,
    status: JobStatus | None = None,
) -> dict:
    """List all scan jobs (for the UI job history panel).

    Search and status predicates are applied by the persistence backend before
    pagination, so totals and exports describe the full filtered collection.

    The store reads run in a worker thread. ``count_summary`` and
    ``count_summary_by_status`` are unbounded aggregates, and the dashboard
    activity feed polls this route continuously, so running them inline would
    stall every unrelated route for the duration of each poll. Backpressure
    sheds excess concurrent reads with ``429 + Retry-After`` rather than piling
    up worker threads — the same guard ``/findings`` uses.
    """
    try:
        async with adaptive_backpressure("jobs"):
            return await anyio.to_thread.run_sync(
                _list_jobs_impl,
                request,
                limit,
                offset,
                include_details,
                q,
                status,
            )
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _list_jobs_impl(
    request: Request,
    limit: int,
    offset: int,
    include_details: bool,
    q: str | None,
    status: JobStatus | None,
) -> dict:
    """Synchronous body of :func:`list_jobs`, run in a worker thread."""
    tenant_id = _tenant_id(request)
    store = _get_store()
    query = q.strip() if q else None
    filter_kwargs: dict[str, Any] = {}
    if query:
        filter_kwargs["query"] = query
    if status is not None:
        filter_kwargs["status"] = status
    count_summary = getattr(store, "count_summary", None)
    if callable(count_summary):
        total = count_summary(tenant_id=tenant_id, **filter_kwargs)
        summary = store.list_summary(tenant_id=tenant_id, limit=limit, offset=offset, **filter_kwargs)
    else:
        summary = store.list_summary(tenant_id=tenant_id)
        if query:
            summary = [
                item
                for item in summary
                if query.casefold()
                in " ".join(str(item.get(key) or "") for key in ("job_id", "source_id", "triggered_by", "schedule_id", "target")).casefold()
            ]
        if status is not None:
            summary = [item for item in summary if item.get("status") == status]
        total = len(summary)
        summary = summary[offset : offset + limit]
    count_summary_by_status = getattr(store, "count_summary_by_status", None)
    if callable(count_summary_by_status):
        # The activity feed polls this route continuously and the aggregate is
        # unbounded, so repeated polls are served from a short-lived cache. A
        # job write drops the tenant's entries. Across workers the guarantee is
        # bounded staleness rather than immediate consistency; seconds is fine
        # for a progress display and nothing gates on this number.
        status_counts = job_status_count_cache.get_counts(tenant_id, query)
        if status_counts is None:
            status_counts = count_summary_by_status(tenant_id=tenant_id, query=query)
            job_status_count_cache.set_counts(tenant_id, query, status_counts)
    else:
        status_counts = {}
    enriched: list[dict[str, Any]] = []
    for item in summary:
        if not include_details:
            enriched.append(item)
            continue
        in_mem = _jobs_get(item["job_id"], tenant_id=tenant_id)
        if isinstance(in_mem, ScanJob) and _visible_to_tenant(in_mem, tenant_id):
            enriched.append(_job_summary_payload(in_mem))
            continue

        # Lightweight stores may expose only summaries. Detail hydration is
        # explicit and bounded by the requested page, independent of cache warmth.
        try:
            get_job = getattr(store, "get", None)
            full_job = get_job(item["job_id"], tenant_id=tenant_id) if callable(get_job) else None
        except Exception:
            full_job = None
        enriched.append(_job_summary_payload(full_job) if isinstance(full_job, ScanJob) else item)
    return {
        # emit schema_version on terminal list responses
        # so downstream consumers can pin a contract independent of API path.
        "schema_version": "v1",
        "jobs": enriched,
        "count": len(enriched),
        "total": total,
        "limit": limit,
        "offset": offset,
        "status_counts": status_counts,
    }


@router.get("/findings", **documented(FindingsResponse), tags=["scan"])
async def list_findings(
    request: Request,
    q: Annotated[str | None, Query(max_length=256)] = None,
    severity: str | None = None,
    scan_id: Annotated[str | None, Query(max_length=128)] = None,
    sort: str = "effective_reach",
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    approximate_total: bool = False,
    provider: Annotated[str | None, Query(max_length=64)] = None,
    account: Annotated[str | None, Query(max_length=256)] = None,
    environment: Annotated[str | None, Query(max_length=64)] = None,
    domain: Annotated[str | None, Query(max_length=32)] = None,
    window_days: Annotated[int | None, Query(ge=0, le=3650)] = None,
    status: Annotated[str, Query(max_length=16)] = _DEFAULT_FINDING_STATUS,
    finding_class: FindingClass | None = None,
    kev: Annotated[bool | None, Query(description="Only known-exploited (KEV) findings, or only non-KEV when false")] = None,
    group_occurrences: Annotated[
        bool,
        Query(description="Group vulnerability occurrences by advisory and package while preserving asset-scoped rows"),
    ] = False,
    framework: Annotated[
        str | None,
        Query(max_length=64, description="Compliance framework drill-through, e.g. soc2 / nist-csf (compliance section id)"),
    ] = None,
    control: Annotated[
        str | None,
        Query(max_length=64, description="Framework control code, narrows within framework (e.g. CC6.1)"),
    ] = None,
    owner: Annotated[str | None, Query(max_length=256)] = None,
    sla: Literal["overdue", "due", "unassigned"] | None = None,
    reachability: Literal["reachable", "unreachable", "unassessed"] | None = None,
    triage: Literal["not_affected", "affected", "under_investigation", "untriaged"] | None = None,
    include_facets: bool = False,
    include: FindingListInclude = None,
    lane: Annotated[
        str | None, Query(max_length=32, description="Finding lane: vulnerabilities, cloud, iac, secrets, identity, data, other")
    ] = None,
) -> dict:
    """List unified findings aggregated from completed scan results.

    Dedup/sort and synchronous store reads run in a worker thread (the context,
    including tenant scope and projection, propagates) to avoid blocking the
    event loop. Adaptive backpressure rejects saturation with 429 + Retry-After.

    Rows carry ``framework_tags`` and ``controls_count``; ``?include=controls``
    restores the full per-finding control mappings.

    ``offset`` is a compatibility path capped at 10,000: past the ceiling the
    endpoint returns ``400`` and steers callers to ``cursor``/``next_cursor``.
    """
    includes = list_include_or_422(include)
    try:
        async with adaptive_backpressure("findings"):
            implementation = _list_finding_groups_impl if group_occurrences else _list_findings_view_impl
            with finding_list_projection(include_controls="controls" in includes):
                body = await anyio.to_thread.run_sync(
                    partial(implementation, lane=lane),
                    request,
                    q,
                    severity,
                    scan_id,
                    sort,
                    limit,
                    offset,
                    cursor,
                    approximate_total,
                    provider,
                    account,
                    environment,
                    domain,
                    window_days,
                    status,
                    finding_class,
                    kev,
                    include_facets,
                    framework,
                    control,
                    owner,
                    sla,
                    reachability,
                    triage,
                )
            body["include"] = list(includes)
            return body
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _project_findings_reachability(
    rows: list[dict[str, Any]],
    *,
    tenant_id: str,
    scan_id: str | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Project persisted paths once for the rows the caller will return.

    Grouped findings walk the occurrence stream in bounded pages. Projecting
    the same persisted graph against every internal 1,000-row page made an
    otherwise linear grouping request pay the graph-join cost dozens of times.
    Callers may now defer this helper until after grouping/pagination, so only
    the visible issue rows receive reachability enrichment.
    """
    warnings: list[str] = []
    try:
        projection = project_persisted_graph_reachability(
            rows,
            graph_store=_get_graph_store(),
            tenant_id=tenant_id,
            scan_id=scan_id,
        )
        if projection.truncated:
            warnings.append(
                "Graph reachability projection is bounded to the highest-risk 1000 persisted paths; unmatched findings remain unassessed."
            )
        return projection.rows, warnings
    except Exception as exc:  # noqa: BLE001 — optional evidence must not fail the findings list
        _logger.warning("Finding graph reachability projection skipped: %s", sanitize_text(sanitize_error(exc)))
        warnings.append("Graph reachability evidence is unavailable for this page; unmatched findings remain unassessed.")
        return rows, warnings


class _FindingListQuery(NamedTuple):
    """Validated, tenant-scoped parameters for one ``/v1/findings`` page."""

    tenant_id: str
    sort_key: str
    severity: str | None
    status_key: str
    scan_id: str | None
    limit: int
    offset: int
    cursor: str | None
    merged_cursor: tuple[int, str] | None
    window_days: int
    window_since: str | None
    scope_filters: dict[str, str]
    approximate_total: bool
    cached_bulk_total: int | None
    include_bulk_total: bool

    @property
    def scan_start(self) -> int:
        return self.merged_cursor[0] if self.merged_cursor is not None else 0

    @property
    def bulk_cursor_in(self) -> str | None:
        # A compound merged cursor carries the hub keyset position; a plain
        # cursor carries only the hub position (the scan half was delivered).
        return (self.merged_cursor[1] or None) if self.merged_cursor is not None else self.cursor


class _FindingListPage(NamedTuple):
    rows: list[dict[str, Any]]
    total: int | None
    total_approximate: bool
    next_cursor: str | None


def _validated_finding_list_params(
    sort: str, severity: str | None, status: str, cursor: str | None, offset: int
) -> tuple[str, str | None, str, tuple[int, str] | None]:
    """Reject bad list parameters with explicit 4xx errors.

    Silently falling back made typos read as "no findings" or "wrong order".
    """
    sort_key = _normalize_finding_sort(sort)
    try:
        severity = canonical_finding_severity_filter(severity)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"invalid severity; accepted values: {', '.join(_ALLOWED_FINDING_SEVERITIES)}",
        ) from None
    status_key = status.strip().lower() if isinstance(status, str) else _DEFAULT_FINDING_STATUS
    if status_key not in _ALLOWED_FINDING_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"invalid status '{status}'; accepted values: {', '.join(_ALLOWED_FINDING_STATUSES)}",
        )
    if cursor and offset:
        raise HTTPException(status_code=400, detail="cursor and offset are mutually exclusive")
    if offset > _HUB_LIST_OFFSET_CEILING:
        # Deep OFFSET scans linearly; cursor pagination is the unbounded-depth contract.
        raise HTTPException(
            status_code=400,
            detail=f"offset exceeds ceiling {_HUB_LIST_OFFSET_CEILING}; use cursor pagination for deeper walks",
        )
    # A cursor is either a compound merged token (scan + hub frontier) or a plain
    # hub keyset cursor. Decode the compound form first so a keyset caller
    # resuming the scan half is routed to the merged walk.
    merged_cursor: tuple[int, str] | None = None
    if cursor:
        try:
            merged_cursor = finding_cursor.decode_merged_scan_cursor(cursor, expected_sort=sort_key)
            if merged_cursor is None:
                finding_cursor.decode_finding_cursor(cursor, expected_sort=sort_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    return sort_key, severity, status_key, merged_cursor


def _finding_list_query(
    request: Request,
    *,
    sort: str,
    severity: str | None,
    status: str,
    scan_id: str | None,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    window_days: int | None,
) -> _FindingListQuery:
    tenant_id = _tenant_id(request)
    # Default read-window (~90d) bounds counts at scale; ``window_days=0`` widens to all history.
    resolved_window = time_window.normalize_window_days(window_days)
    window_since = time_window.window_since_iso(resolved_window)
    sort_key, severity, status_key, merged_cursor = _validated_finding_list_params(sort, severity, status, cursor, offset)
    effective_approximate_total = findings_count_cache.resolve_effective_approximate_total(
        requested=approximate_total,
        tenant_id=tenant_id,
        severity=severity,
        scan_id=scan_id,
        window_days=resolved_window,
        status=status_key,
    )
    cached_bulk_total = findings_count_cache.get_cached_total(
        findings_count_cache.cache_key(
            tenant_id=tenant_id,
            severity=severity,
            scan_id=scan_id,
            origin="bulk_ingest",
            window_days=resolved_window,
            status=status_key,
        )
    )
    approximate = bool(approximate_total or effective_approximate_total)
    # Approximate reads reuse cached totals; warm the cache with one exact count
    # only when it is cold on the first page.
    include_bulk_total = not cursor and cached_bulk_total is None and (offset == 0 or not approximate)
    return _FindingListQuery(
        tenant_id=tenant_id,
        sort_key=sort_key,
        severity=severity,
        status_key=status_key,
        scan_id=scan_id,
        limit=limit,
        offset=offset,
        cursor=cursor,
        merged_cursor=merged_cursor,
        window_days=resolved_window,
        window_since=window_since,
        scope_filters={},
        approximate_total=approximate,
        cached_bulk_total=cached_bulk_total,
        include_bulk_total=include_bulk_total,
    )


def _filter_finding_rows(rows: list[dict[str, Any]], query: _FindingListQuery) -> list[dict[str, Any]]:
    """Apply severity, lifecycle status and scope filters to in-memory rows."""
    if query.severity:
        normalized = query.severity.lower()
        rows = [item for item in rows if str(item.get("severity", "")).lower() == normalized]
    # Scan findings carry no lifecycle status, so they count as ``open``.
    rows = [item for item in rows if compliance_hub_store.status_matches(item, query.status_key)]
    if query.scope_filters:
        rows = [item for item in rows if _row_matches_scope(item, query.scope_filters)]
    return rows


def _scan_half_rows(query: _FindingListQuery, store: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Current-state scan findings for the page, sorted for the merged walk.

    The default view collapses re-scans to the current state per finding;
    ``?scan_id=`` returns that scan's rows verbatim.
    """
    if query.cursor and query.merged_cursor is None:
        # A plain hub keyset cursor: the scan half was delivered on earlier
        # merged pages, so skip the O(all-completed-jobs) fold entirely.
        if _completed_jobs_for_tenant(query.tenant_id):
            warnings.append("cursor pagination applies to bulk-ingested findings only; in-memory scan findings appear on the first page")
        return []

    def load() -> list[dict[str, Any]]:
        rows = _current_scan_rows(query.tenant_id, query.window_since, query.scan_id)
        rows = findings_current.scan_only_findings(rows, query.tenant_id, hub=store, scan_id=query.scan_id)
        rows = _filter_finding_rows(rows, query)
        rows.sort(key=lambda row: _finding_sort_key(row, query.sort_key))
        return rows

    # View filters and issue grouping page through up to 50k rows in one read;
    # fold, filter and sort the scan half once per read instead of once per page.
    # Callers only index into or copy the returned list.
    key = [query.tenant_id, query.window_since, query.scan_id, query.severity, query.status_key, query.sort_key]
    return read_once(("scan_half_rows", json.dumps([*key, sorted(query.scope_filters.items())])), load)


def _merged_page_next_cursor(query: _FindingListQuery, page: MergedScanBulkPage) -> str | None:
    if not page.has_more:
        return None
    return finding_cursor.encode_merged_scan_cursor(sort=query.sort_key, scan_index=page.next_scan_index, bulk_cursor=page.next_bulk_cursor)


def _merged_page(
    query: _FindingListQuery,
    scan_findings: list[dict[str, Any]],
    bulk_list: Callable[..., Any],
    **scope_kwargs: Any,
) -> tuple[list[dict[str, Any]], str | None]:
    merged = _merged_scan_bulk_page(
        scan_findings,
        bulk_list=bulk_list,
        tenant_id=query.tenant_id,
        sort_key=query.sort_key,
        severity=query.severity,
        scan_id=query.scan_id,
        offset=query.offset,
        limit=query.limit,
        scan_start=query.scan_start,
        bulk_cursor=query.bulk_cursor_in,
        since=query.window_since,
        status=query.status_key,
        **scope_kwargs,
    )
    return merged.rows, _merged_page_next_cursor(query, merged)


def _bulk_page(query: _FindingListQuery, bulk_list: Callable[..., Any], **kwargs: Any) -> tuple[list[dict[str, Any]], Any, str | None]:
    """One keyset/offset page from the hub's bulk-ingest source."""
    result = bulk_list(
        query.tenant_id,
        limit=query.limit,
        offset=0 if query.cursor else query.offset,
        sort=query.sort_key,
        severity=query.severity,
        scan_id=query.scan_id,
        origin="bulk_ingest",
        cursor=query.bulk_cursor_in,
        since=query.window_since,
        status=query.status_key,
        **kwargs,
    )
    return result[0], result[1], (result[2] if len(result) > 2 else None)


def _scoped_findings_page(
    query: _FindingListQuery,
    scan_findings: list[dict[str, Any]],
    bulk_list: Callable[..., Any],
    *,
    use_merged: bool,
    scope_metadata: dict[str, Any],
) -> _FindingListPage:
    """Scope filters run inside the store, batched and keyset-paged.

    Scope keys live in the payload or are computed, so they cannot be one SQL
    predicate; the walk stays on the keyset path and ``total`` is approximate.
    """
    scope_kwargs = {"scope": dict(query.scope_filters), "scope_metadata": scope_metadata}
    if use_merged:
        rows, next_cursor = _merged_page(query, scan_findings, bulk_list, **scope_kwargs)
    else:
        rows, _total, next_cursor = _bulk_page(query, bulk_list, include_total=False, **scope_kwargs)
    return _FindingListPage(rows=rows, total=None, total_approximate=True, next_cursor=next_cursor)


def _merged_unscoped_page(query: _FindingListQuery, scan_findings: list[dict[str, Any]], bulk_list: Callable[..., Any]) -> _FindingListPage:
    if query.merged_cursor is not None:
        # Resume pages stay approximate to avoid an O(table) count per page.
        rows, next_cursor = _merged_page(query, scan_findings, bulk_list)
        return _FindingListPage(rows=rows, total=None, total_approximate=True, next_cursor=next_cursor)
    probe = bulk_list(
        query.tenant_id,
        limit=1,
        offset=0,
        sort=query.sort_key,
        severity=query.severity,
        scan_id=query.scan_id,
        origin="bulk_ingest",
        include_total=query.include_bulk_total,
        since=query.window_since,
        status=query.status_key,
    )
    rows, next_cursor = _merged_page(query, scan_findings, bulk_list)
    resolved_bulk, total_approximate = _resolve_bulk_findings_total(
        tenant_id=query.tenant_id,
        severity=query.severity,
        scan_id=query.scan_id,
        approximate_total=query.approximate_total,
        offset=query.offset,
        bulk_total=probe[1],
        request_cached_total=query.cached_bulk_total,
        page_len=len(rows),
        limit=query.limit,
        window_days=query.window_days,
        status=query.status_key,
    )
    total = None if resolved_bulk is None else len(scan_findings) + resolved_bulk
    return _FindingListPage(rows=rows, total=total, total_approximate=total_approximate, next_cursor=next_cursor)


def _bulk_only_page(query: _FindingListQuery, bulk_list: Callable[..., Any]) -> _FindingListPage:
    rows, bulk_total, next_cursor = _bulk_page(query, bulk_list, include_total=query.include_bulk_total)
    total, total_approximate = _resolve_bulk_findings_total(
        tenant_id=query.tenant_id,
        severity=query.severity,
        scan_id=query.scan_id,
        approximate_total=query.approximate_total,
        offset=0 if query.cursor else query.offset,
        bulk_total=bulk_total,
        request_cached_total=query.cached_bulk_total,
        page_len=len(rows),
        limit=query.limit,
        window_days=query.window_days,
        status=query.status_key,
    )
    return _FindingListPage(rows=rows, total=total, total_approximate=total_approximate, next_cursor=next_cursor)


def _in_memory_findings_page(query: _FindingListQuery, scan_findings: list[dict[str, Any]]) -> _FindingListPage:
    """Store without keyset paging: materialize, sort and walk by index.

    The merged cursor's ``scan_index`` slot doubles as the index so
    ``has_more`` stays honest and the rest is retrievable.
    """
    bulk_findings = _bulk_ingested_findings_for_tenant(query.tenant_id)
    if query.scan_id:
        bulk_findings = [item for item in bulk_findings if str(item.get("scan_id") or "") == query.scan_id]
    combined = scan_findings + _filter_finding_rows(bulk_findings, query)
    combined.sort(key=lambda row: _finding_sort_key(row, query.sort_key))
    start = query.scan_start if query.merged_cursor is not None else query.offset
    rows = combined[start : start + query.limit]
    end = start + len(rows)
    next_cursor = (
        finding_cursor.encode_merged_scan_cursor(sort=query.sort_key, scan_index=end, bulk_cursor="") if end < len(combined) else None
    )
    return _FindingListPage(rows=rows, total=len(combined), total_approximate=False, next_cursor=next_cursor)


def _findings_page(
    query: _FindingListQuery,
    scan_findings: list[dict[str, Any]],
    store: Any,
    scope_metadata: dict[str, Any],
) -> _FindingListPage:
    """Pick the page strategy the store supports for this query."""
    bulk_list = getattr(store, "list_current_page", None) or getattr(store, "list_page", None)
    has_current_page = callable(getattr(store, "list_current_page", None))
    # Take the merged (scan + hub) keyset walk whenever the scan half is in play.
    use_merged = has_current_page and (query.merged_cursor is not None or (not query.cursor and bool(scan_findings)))
    if query.scope_filters and has_current_page and callable(bulk_list):
        return _scoped_findings_page(query, scan_findings, bulk_list, use_merged=use_merged, scope_metadata=scope_metadata)
    if callable(bulk_list) and not query.scope_filters:
        if use_merged:
            return _merged_unscoped_page(query, scan_findings, bulk_list)
        return _bulk_only_page(query, bulk_list)
    return _in_memory_findings_page(query, scan_findings)


def _apply_finding_facets(query: _FindingListQuery, page: _FindingListPage, warnings: list[str]) -> tuple[_FindingListPage, dict, dict]:
    facets, facet_total, completeness = _finding_facets_bounded(
        query.tenant_id,
        severity=query.severity,
        scan_id=query.scan_id,
        since=query.window_since,
        scope=query.scope_filters,
        status=query.status_key,
    )
    # A bounded walk is a lower bound; only a complete walk or an
    # aggregate-derived exact total may replace the list path's total.
    if completeness["status"] == "complete" or completeness["total_exact"]:
        page = page._replace(total=facet_total, total_approximate=not completeness["total_exact"])
    if completeness["status"] != "complete":
        bounded = sorted(name for name, state in completeness["dimensions"].items() if state == "bounded")
        warnings.append(
            "Facet counting stopped after "
            f"{completeness['scanned_rows']} scanned rows ({completeness['reason']}); "
            f"these facet counts are lower bounds, not totals: {', '.join(bounded)}."
        )
    return page, facets, completeness


def _scope_completeness(scope_metadata: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    truncated = bool(scope_metadata.get("truncated"))
    completeness = {
        "status": "partial" if truncated else "complete",
        "reason": str(scope_metadata.get("reason") or ""),
        "scanned_rows": int(scope_metadata.get("scanned_rows") or 0),
        "scan_budget": int(scope_metadata.get("scan_budget") or 0),
    }
    if truncated:
        warnings.append(
            "Scope filter matching stopped after "
            f"{completeness['scanned_rows']} scanned rows ({completeness['reason']}); "
            "this page is partial — continue with next_cursor for the rest."
        )
    return completeness


def _attach_facets(envelope: dict[str, Any], facets: dict, completeness: dict) -> None:
    envelope["facets"] = facets
    envelope["facets_approximate"] = completeness["status"] != "complete"
    envelope["facet_metadata"] = {
        "freshness": {
            "basis": ["last_observed", "last_seen"],
            "thresholds_hours": [24, 168, 720],
            "missing_or_invalid": "unavailable",
        },
        "completeness": completeness,
    }


def _findings_page_envelope(
    query: _FindingListQuery,
    page: _FindingListPage,
    rows: list[dict[str, Any]],
    *,
    filters: dict[str, Any],
    warnings: list[str],
    walk_truncated: bool = False,
) -> dict[str, Any]:
    total, total_approximate = page.total, page.total_approximate
    if total is None and not (page.next_cursor or query.cursor or query.offset or walk_truncated):
        # A first page with no continuation saw every match, so its size is exact.
        total, total_approximate = len(page.rows), False
    envelope = finding_list_envelope(
        findings=rows,
        total=total,
        limit=query.limit,
        offset=0 if query.cursor else query.offset,
        sort=query.sort_key,
        scan_id=query.scan_id,
        cursor=query.cursor or "",
        next_cursor=page.next_cursor or "",
        filters=filters,
        warnings=warnings,
        total_approximate=total_approximate,
        source="scan_and_current_ingest_findings",
        scope="tenant current-state findings",
    )
    # Echo the applied read-window so clients label counts as "last Nd", not "all".
    envelope["window"] = time_window.window_metadata(query.window_days)
    envelope["count_metadata"]["window"] = envelope["window"]
    return envelope


def _list_findings_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    project_graph_reachability: bool = True,
    redact_page: bool = True,
    lane: str | None = None,
) -> dict:
    """Synchronous body of :func:`list_findings` (runs in a worker thread).

    Default sort is ``effective_reach``; ``?sort=cvss`` and ``?sort=severity``
    give CVSS-only and severity-band ordering. ``?approximate_total=true`` (and
    tenants above ``AGENT_BOM_FINDINGS_APPROXIMATE_TOTAL_THRESHOLD``) reuse
    cached totals instead of ``COUNT(*)``. ``?cursor=`` resumes the keyset walk
    from a prior ``next_cursor`` and cannot be combined with ``offset``.
    """
    query = _finding_list_query(
        request,
        sort=sort,
        severity=severity,
        status=status,
        scan_id=scan_id,
        limit=limit,
        offset=offset,
        cursor=cursor,
        approximate_total=approximate_total,
        window_days=window_days,
    )
    scope_filters = _canonical_scope_filters(
        provider, account, environment, domain, finding_class, q, kev, framework, control, owner, sla, lane
    )
    query = query._replace(scope_filters=scope_filters)
    store = compliance_hub_store.get_compliance_hub_store()
    warnings: list[str] = []
    scope_metadata: dict[str, Any] = {}
    scan_findings = _scan_half_rows(query, store, warnings)
    page = _findings_page(query, scan_findings, store, scope_metadata)
    facet_result: tuple[dict, dict] | None = None
    if include_facets:
        page, facets, completeness = _apply_finding_facets(query, page, warnings)
        facet_result = (facets, completeness)
    rows = page.rows
    if project_graph_reachability:
        rows, reachability_warnings = _project_findings_reachability(rows, tenant_id=query.tenant_id, scan_id=scan_id)
        warnings.extend(reachability_warnings)
    scope_completeness = _scope_completeness(scope_metadata, warnings) if scope_filters and scope_metadata else None
    # Internal aggregate callers may defer the default-deny projection; public callers keep it.
    rows = project_current_suppressions(rows, query.tenant_id)
    envelope = _findings_page_envelope(
        query,
        page,
        _redact_finding_page(rows) if redact_page else rows,
        filters=_finding_list_filters(finding_class, q, framework, control, owner, sla, severity=query.severity, scope=scope_filters),
        warnings=warnings,
        walk_truncated=bool(scope_metadata.get("truncated")),
    )
    if scope_completeness is not None:
        envelope["scope_completeness"] = scope_completeness
    if facet_result is not None:
        _attach_facets(envelope, *facet_result)
    return envelope


@finding_read_snapshot
def _list_findings_view_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    reachability: str | None = None,
    triage: str | None = None,
    project_graph_reachability: bool = True,
    redact_page: bool = True,
    lane: str | None = None,
) -> dict[str, Any]:
    """Apply evidence-backed view filters before pagination.

    Reachability is graph-derived and triage lives in the exception store, so
    neither can be pushed into the canonical finding store query. Walk the
    canonical keyset stream instead; this preserves occurrence IDs and avoids
    the dishonest client-side filtering of an already-selected page.
    """
    query_kw = dict(q=q, severity=severity, scan_id=scan_id, sort=sort, window_days=window_days, finding_class=finding_class, kev=kev)
    scope_kw = dict(
        provider=provider, account=account, environment=environment, domain=domain, framework=framework, control=control, lane=lane
    )
    tail_kw = dict(owner=owner, sla=sla, project_graph_reachability=project_graph_reachability, redact_page=redact_page)
    common: dict[str, Any] = {**query_kw, **scope_kw, **tail_kw}
    suppressed_only = status.strip().lower() == "suppressed"
    if reachability is None and triage is None and not suppressed_only:
        return _list_findings_impl(
            request,
            limit=limit,
            offset=offset,
            cursor=cursor,
            approximate_total=approximate_total,
            status=status,
            include_facets=include_facets,
            **common,
        )

    from agent_bom.api.routes.enterprise import build_tenant_triage_state_index

    def fetch_page(page_limit: int, source_cursor: str | None) -> dict[str, Any]:
        # ``open`` excludes suppressed evidence, so the suppressed view walks every lifecycle row.
        page_status = "all" if suppressed_only else status
        return _list_findings_impl(
            request,
            limit=page_limit,
            offset=0,
            cursor=source_cursor,
            approximate_total=True,
            status=page_status,
            include_facets=False,
            **common,
        )

    triage_index = build_tenant_triage_state_index(_tenant_id(request)) if triage is not None else None
    row_filter = partial(
        _view_filtered_row, triage_index=triage_index, reachability=reachability, triage=triage, suppressed_only=suppressed_only
    )
    walk = _walk_view_filtered_findings(fetch_page, row_filter, target=limit if cursor else offset + limit, cursor=cursor)
    filters = _view_filters(walk.first_page, suppressed_only=suppressed_only, reachability=reachability, triage=triage)
    return _view_envelope(walk, limit=limit, offset=offset, cursor=cursor, sort=sort, scan_id=scan_id, filters=filters)


@finding_read_snapshot
def _list_finding_groups_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    reachability: str | None = None,
    triage: str | None = None,
    lane: str | None = None,
) -> dict[str, Any]:
    """Build a bounded server-side issue queue over canonical occurrence rows.

    Raw ``GET /v1/findings`` remains the authoritative per-asset workflow
    surface. This view walks that exact filtered queue, groups only rows sharing
    the canonical asset-independent issue identity, and returns bounded
    occurrence summaries for expansion. A row-budget hit is explicit partial
    evidence; it is never described as a complete group count.
    """
    sort_key = _normalize_finding_sort(sort)
    group_offset = _finding_group_offset(cursor, offset, sort_key)

    def fetch_page(budget: int, source_cursor: str | None, first: bool) -> dict[str, Any]:
        # Severity applies after grouping so the issue histogram stays
        # self-excluding: two occurrences of one advisory are one issue.
        head = (q, None, scan_id, sort_key, budget, 0, source_cursor, True, provider, account, environment, domain, window_days, status)
        tail = (finding_class, kev, include_facets and first, framework, control, owner, sla, reachability, triage, False, False)
        return _list_findings_view_impl(request, *head, *tail)

    rows, first_page, warnings, source_cursor = _collect_group_occurrences(fetch_page)
    all_groups = _group_occurrence_rows(rows)
    normalized_severity = severity.strip().lower() if severity and severity.strip() else None
    groups, all_groups, counts_by_lane = select_group_lane(all_groups, normalized_severity, lane)
    truncated = source_cursor is not None
    if truncated:
        warnings.append("Issue grouping stopped after 50,000 occurrence rows; group and occurrence counts are lower bounds.")
    page_groups, reachability_warnings = _project_findings_reachability(
        groups[group_offset : group_offset + limit], tenant_id=_tenant_id(request), scan_id=scan_id
    )
    page_groups = [_serialize_finding_group(group) for group in page_groups]
    warnings.extend(reachability_warnings)
    next_offset = group_offset + len(page_groups)
    next_cursor = finding_cursor.encode_finding_group_cursor(sort=sort_key, offset=next_offset) if next_offset < len(groups) else ""
    envelope = _groups_envelope(
        page_groups,
        first_page=first_page,
        total=len(groups),
        limit=limit,
        offset=0 if cursor else offset,
        sort=sort_key,
        scan_id=scan_id,
        cursor=cursor,
        next_cursor=next_cursor,
        warnings=warnings,
        severity=normalized_severity,
        truncated=truncated,
    )
    severity_counts = _grouped_severity_counts(all_groups) if include_facets else None
    _attach_grouping_metadata(
        envelope, first_page=first_page, groups=groups, scanned=len(rows), truncated=truncated, severity_counts=severity_counts
    )
    attach_lane_counts(envelope, lane, counts_by_lane, truncated, include_facets)
    return envelope


def issue_severity_counts(request: Request) -> dict[str, Any]:
    """Open issue-group severity counts for the findings page default query.

    Nav badges and the overview read this so their numbers equal what the
    grouped ``/v1/findings`` view shows with no filters applied: the same
    tenant, default read window, open status and canonical issue grouping.
    """
    page = _list_finding_groups_impl(
        request,
        None,
        None,
        None,
        _normalize_finding_sort("severity"),
        1,
        0,
        None,
        True,
        include_facets=True,
    )
    severity = (page.get("facets") or {}).get("severity") or {}
    counts: dict[str, Any] = {key: int(severity.get(key) or 0) for key in ("critical", "high", "medium", "low")}
    counts["unrated"] = int(severity.get("info") or 0) + int(severity.get("unknown") or 0)
    counts["total"] = int(page.get("total") or 0)
    counts["approximate"] = bool(page.get("total_approximate"))
    counts["window"] = page.get("window")
    counts["basis"] = "issue_groups"
    return counts


@finding_read_snapshot
def current_findings_snapshot(
    request: Request,
    *,
    max_findings: int = 50_000,
    q: str | None = None,
    severity: str | None = None,
    scan_id: str | None = None,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    reachability: str | None = None,
    triage: str | None = None,
    project_graph_reachability: bool = True,
    row_projection: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    lane: str | None = None,
) -> dict[str, Any]:
    """Collect the canonical current finding queue for an internal consumer.

    Uses the same merged scan + current-ingest keyset stream as GET /v1/findings.
    A bound hit is explicit partial evidence, never a complete snapshot.
    """
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
    first_total: int | None = None
    first_metadata: dict[str, Any] | None = None
    warnings: list[str] = []
    while len(rows) < max_findings:
        page = _list_findings_view_impl(
            request,
            q=q,
            severity=severity,
            scan_id=scan_id,
            sort="effective_reach",
            limit=min(1000, max_findings - len(rows)),
            offset=0,
            cursor=cursor,
            approximate_total=cursor is not None,
            provider=provider,
            account=account,
            environment=environment,
            domain=domain,
            window_days=window_days,
            status=status,
            finding_class=finding_class,
            kev=kev,
            framework=framework,
            control=control,
            owner=owner,
            sla=sla,
            reachability=reachability,
            triage=triage,
            project_graph_reachability=project_graph_reachability or reachability is not None,
            redact_page=row_projection is None,
            lane=lane,
        )
        if first_metadata is None:
            first_metadata = page.get("count_metadata") if isinstance(page.get("count_metadata"), dict) else {}
            first_total = page.get("total") if isinstance(page.get("total"), int) else None
        page_rows = page.get("findings")
        if isinstance(page_rows, list):
            rows.extend((row_projection(row) if row_projection else row) for row in page_rows if isinstance(row, dict))
        warnings.extend(str(item) for item in page.get("warnings", []) if str(item))
        cursor = str(page.get("next_cursor") or "") or None
        if not cursor:
            break

    tenant_id = _tenant_id(request)
    retained_jobs = _completed_jobs_for_tenant(tenant_id)
    jobs = (
        current_scan_jobs(retained_jobs, since=None, scan_id=scan_id)
        if scan_id
        else _finding_snapshot_jobs(retained_jobs, since=None, require_authoritative_evidence=True)[0]
    )
    return snapshot_envelope(
        tenant_id=tenant_id,
        rows=rows,
        jobs=jobs,
        first_total=first_total,
        first_metadata=first_metadata,
        cursor=cursor,
        max_findings=max_findings,
        warnings=warnings,
    )


@router.post(
    "/findings/bulk",
    tags=["scan"],
    status_code=201,
    dependencies=[Depends(_require_json_content_type)],
)
async def ingest_bulk_findings(request: Request, body: BulkFindingsRequest) -> dict:
    """Append normalized findings for the request tenant.

    This is the agent-native counterpart to `/v1/compliance/ingest`: callers
    that already have normalized finding objects can post them directly instead
    of wrapping them as SARIF/CycloneDX/CSV content. Request authentication owns
    the tenant scope; `tenant_id` in the JSON body is accepted only for legacy
    clients and is never trusted for routing.
    """
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    tenant_id = _tenant_id(request)
    require_body_tenant_match(body.tenant_id, tenant_id)

    # Batch-level replay safety: an identical retry under the same
    # Idempotency-Key returns the first cached response (same batch_id and
    # counts); a reused key with a different body is a 409 conflict. This is
    # additive to the row-level (tenant_id, finding_id) collapse below.
    idem_key = _request_header(request, "Idempotency-Key")
    idem_source = _request_header(request, "X-Agent-Bom-Source-Id") or "bulk-ingest"
    request_hash = idempotency_request_fingerprint(body)
    if idem_key:
        try:
            cached = _get_idempotency_store().get(
                "/v1/findings/bulk",
                tenant_id,
                idem_source,
                idem_key,
                request_hash=request_hash,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
        if cached is not None:
            cached["idempotent_replay"] = True
            return cast(dict, cached)

    # Deterministic batch id so a resend of the same body (even without an
    # Idempotency-Key header) collapses onto one logical batch. Random per-request
    # ids made ``upsert_current_batch``'s (canonical, batch_id) observation key
    # miss on every replay, inflating ``scan_count`` (P1-5).
    batch_id = deterministic_batch_id(idem_key or request_hash)
    payloads = [
        _normalized_bulk_finding(row, source=body.source, batch_id=batch_id, ordinal=idx) for idx, row in enumerate(body.findings, start=1)
    ]
    from agent_bom.api.finding_lifecycle import normalize_observed_at

    observed_at = normalize_observed_at(body.observed_at or body.metadata.get("observed_at"))
    hub_store = get_compliance_hub_store()

    # Offload the blocking psycopg write sequence (ledger append + current-state
    # upsert + reconcile + delta emission) to a worker thread so concurrent bulk
    # ingest cannot freeze the event loop and unrelated requests (mirrors the
    # read path). See ``_bulk_ingest_store_writes`` / ``_hub_store_call``.
    from agent_bom.api.hub_observations_partition import (
        ObservationPartitionRangeError,
        ObservationPartitionUnavailableError,
    )

    try:
        store_result = await _hub_store_call(
            _bulk_ingest_store_writes,
            hub_store,
            tenant_id,
            payloads,
            observed_at=observed_at,
            batch_id=batch_id,
            source=body.source,
            reconcile_absent=body.reconcile_absent,
        )
    except ObservationPartitionRangeError as exc:
        # observed_at is so far past/future it is almost certainly bad data — a
        # clean 4xx instead of a raw partition CheckViolation 500.
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    except ObservationPartitionUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail="Observation storage is not provisioned for this timestamp; run database migrations.",
        ) from exc
    new_total = store_result["new_total"]
    reconciled = store_result["reconciled"]
    delta_results = store_result["delta_results"]
    distinct_findings = store_result["distinct_findings"]
    duplicate_payloads = store_result["duplicate_payloads"]
    warnings: list[str] = []
    if duplicate_payloads:
        warnings.append(
            f"{duplicate_payloads} duplicate payload(s) collapsed onto an existing canonical id; "
            f"{distinct_findings} distinct finding(s) were stored"
        )
    response = {
        "schema_version": "v1",
        "batch_id": batch_id,
        "ingested": len(payloads),
        "distinct_findings": distinct_findings,
        "duplicate_payloads": duplicate_payloads,
        "tenant_total": new_total,
        "tenant_id": tenant_id,
        "source": body.source,
        "observed_at": observed_at,
        "warnings": warnings,
    }
    if body.reconcile_absent:
        response["reconciled"] = reconciled
    if delta_results:
        delivered = sum(
            1
            for result in delta_results
            if (result.get("status") == "delivered" if isinstance(result, dict) else getattr(result, "delivered", False))
        )
        response["delta_stream"] = {"emitted_batches": len(delta_results), "delivered": delivered}
    if idem_key:
        _get_idempotency_store().put(
            "/v1/findings/bulk",
            tenant_id,
            idem_source,
            idem_key,
            response,
            request_hash=request_hash,
        )
    return response


@router.get("/inventory", tags=["scan"], response_model=InventoryResponse)
def list_inventory(
    request: Request,
    # enforce limit cap server-side via Pydantic.
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List agent and package inventory aggregated from completed scan results."""
    from agent_bom.api.estate_agents import scanned_estate_agents

    tenant_id = _tenant_id(request)
    completed = _completed_jobs_for_tenant(tenant_id)
    # One canonical agent is one row however many scans observed it; batch
    # parents are skipped because their children already carry the agents.
    agents = scanned_estate_agents(completed)
    jobs: list[dict[str, str]] = [
        {"job_id": job.job_id, "created_at": job.created_at, "completed_at": job.completed_at or ""}
        for job in completed
        if not job.child_job_ids and any(isinstance(item, dict) for item in (job.result or {}).get("agents", []) or [])
    ]

    packages = _inventory_packages_from_agents(agents)
    total = len(agents)
    package_total = len(packages)
    job_total = len(jobs)
    page = agents[offset : offset + limit]
    packages_page = packages[offset : offset + limit]
    jobs_page = jobs[offset : offset + limit]
    return {
        # Scope marker so callers never conflate this population with live
        # local-disk discovery at /v1/agents. This endpoint is the scanned
        # estate: agents/packages aggregated from completed scan jobs.
        "scope": "scanned_estate",
        "source": (
            "Agents and packages aggregated from completed scan jobs (the scanned "
            "estate). For live local-disk discovery of AI-client configs on this "
            "host, see /v1/agents."
        ),
        "agents": page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
        # Honest truncation across the three roll-up arrays that share this
        # offset/limit window (fleet-style list contract).
        "has_more": offset + len(page) < total or offset + len(packages_page) < package_total or offset + len(jobs_page) < job_total,
        "packages": packages_page,
        "package_count": len(packages_page),
        "package_total": package_total,
        "jobs": jobs_page,
        "job_count": len(jobs_page),
        "job_total": job_total,
        "warnings": [],
    }


# ─── Dedicated Scan Endpoints ─────────────────────────────────────────────────
# Lightweight, synchronous scans for specific asset types.
# Each returns results directly (no job queue — these are fast local scans).
