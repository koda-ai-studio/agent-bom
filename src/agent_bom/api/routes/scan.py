"""Scan submission, status, findings, inventory, exports and auxiliary scanner routes."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from functools import partial
from importlib import import_module
from typing import Annotated, Any, Literal, cast

import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from agent_bom.api import job_status_count_cache
from agent_bom.api.bulk_findings_ingest import BulkFindingsRequest, PackageCheckRequest, _normalized_bulk_finding
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
from agent_bom.api.finding_list_helpers import _DEFAULT_FINDING_STATUS
from agent_bom.api.finding_list_projection import FindingListInclude, finding_list_projection, list_include_or_422
from agent_bom.api.finding_merge import _BULK_MERGE_CHUNK as _BULK_MERGE_CHUNK
from agent_bom.api.finding_merge import MergedScanBulkPage as MergedScanBulkPage
from agent_bom.api.finding_merge import _merge_bulk_kwargs as _merge_bulk_kwargs
from agent_bom.api.finding_merge import _merged_scan_bulk_page as _merged_scan_bulk_page
from agent_bom.api.finding_merge import _resolve_bulk_findings_total as _resolve_bulk_findings_total
from agent_bom.api.finding_merge import _ScanBulkMerge as _ScanBulkMerge
from agent_bom.api.finding_page_read import _list_finding_groups_impl, _list_findings_view_impl
from agent_bom.api.finding_scope_filters import _canonical_group_key as _canonical_group_key
from agent_bom.api.finding_scope_filters import _canonical_scope_filters as _canonical_scope_filters
from agent_bom.api.finding_scope_filters import _finding_identity as _finding_identity
from agent_bom.api.finding_scope_filters import _finding_list_filters as _finding_list_filters
from agent_bom.api.finding_scope_filters import _finding_sort_key as _finding_sort_key
from agent_bom.api.finding_scope_filters import _row_asset_key as _row_asset_key
from agent_bom.api.finding_scope_filters import _row_matches_scope as _row_matches_scope
from agent_bom.api.finding_view_filters import _FINDINGS_VIEW_FILTER_MAX_ROWS as _FINDINGS_VIEW_FILTER_MAX_ROWS
from agent_bom.api.finding_view_filters import _copy_first_page_metadata as _copy_first_page_metadata
from agent_bom.api.finding_view_filters import _finding_triage_state as _finding_triage_state
from agent_bom.api.finding_view_filters import _matches_reachability as _matches_reachability
from agent_bom.api.finding_view_filters import _view_envelope as _view_envelope
from agent_bom.api.finding_view_filters import _view_filtered_row as _view_filtered_row
from agent_bom.api.finding_view_filters import _view_filters as _view_filters
from agent_bom.api.finding_view_filters import _ViewWalk as _ViewWalk
from agent_bom.api.finding_view_filters import _walk_view_filtered_findings as _walk_view_filtered_findings
from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyReservationHeartbeat,
    deterministic_batch_id,
    idempotency_owner_token,
    idempotency_request_fingerprint,
    idempotency_reservation_lease_seconds,
)
from agent_bom.api.models import InventoryResponse, JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import request_scan_cancellation
from agent_bom.api.read_models import FindingsResponse, JobsResponse, documented
from agent_bom.api.read_models.scan import ScanDriversResponse, ScanStatusResponse
from agent_bom.api.routes.scan_exports import router as exports_router
from agent_bom.api.scan_cohorts import correlation_cohort_id as correlation_cohort_id
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
from agent_bom.api.scan_job_dispatch import _repair_scan_batch
from agent_bom.api.scan_job_submission import enqueue_scan_job
from agent_bom.api.scan_job_views import _inventory_packages_from_agents, _job_response_payload, _job_summary_payload
from agent_bom.api.scan_request_context import (
    _bulk_ingest_store_writes,
    _hub_store_call,
    _job_response_payload_off_loop,
    _load_job_for_request,
    _logger,
    _request_header,
    _require_json_content_type,
    _sanitize_scan_request_paths,
    _tenant_id,
    _triggered_by,
    _visible_to_tenant,
)
from agent_bom.api.stores import _get_idempotency_store, _get_store, _job_lock, _jobs_get, _jobs_pop
from agent_bom.api.tenancy import require_body_tenant_match
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.finding_scope import FindingClass
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()


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


router.include_router(exports_router)


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


_EXPORTS = {
    "refresh_batch_parent": "agent_bom.api.scan_batches",
    "_FindingListQuery": "agent_bom.api.finding_page_query",
    "_FindingListPage": "agent_bom.api.finding_page_query",
    "_validated_finding_list_params": "agent_bom.api.finding_page_query",
    "_finding_list_query": "agent_bom.api.finding_page_query",
    "_filter_finding_rows": "agent_bom.api.finding_page_filters",
    "_scan_half_rows": "agent_bom.api.finding_page_filters",
    "_merged_page_next_cursor": "agent_bom.api.finding_page_filters",
    "_merged_page": "agent_bom.api.finding_page_filters",
    "_bulk_page": "agent_bom.api.finding_page_filters",
    "_scoped_findings_page": "agent_bom.api.finding_page_filters",
    "_merged_unscoped_page": "agent_bom.api.finding_page_filters",
    "_bulk_only_page": "agent_bom.api.finding_page_filters",
    "_in_memory_findings_page": "agent_bom.api.finding_page_filters",
    "_findings_page": "agent_bom.api.finding_page_filters",
    "_redact_finding_page": "agent_bom.api.finding_page_read",
    "_project_findings_reachability": "agent_bom.api.finding_page_read",
    "_apply_finding_facets": "agent_bom.api.finding_page_read",
    "_scope_completeness": "agent_bom.api.finding_page_read",
    "_attach_facets": "agent_bom.api.finding_page_read",
    "_findings_page_envelope": "agent_bom.api.finding_page_read",
    "_list_findings_impl": "agent_bom.api.finding_page_read",
    "_SCAN_LOCAL_PATH_SINGLE_FIELDS": "agent_bom.api.scan_request_context",
    "_SCAN_LOCAL_PATH_LIST_FIELDS": "agent_bom.api.scan_request_context",
    "_job_for_request": "agent_bom.api.scan_request_context",
    "_cohort_manifest": "agent_bom.api.scan_cohort_submission",
    "enqueue_correlation_cohort": "agent_bom.api.scan_cohort_submission",
    "dispatch_scan_job": "agent_bom.api.scan_job_dispatch",
    "get_attack_flow": "agent_bom.api.routes.scan_exports",
    "get_context_graph": "agent_bom.api.routes.scan_exports",
    "get_graph_export": "agent_bom.api.routes.scan_exports",
    "get_scan_agent_bom": "agent_bom.api.routes.scan_exports",
    "get_current_remediation": "agent_bom.api.routes.scan_exports",
    "get_remediation_plan": "agent_bom.api.routes.scan_exports",
    "get_licenses": "agent_bom.api.routes.scan_exports",
    "get_vex": "agent_bom.api.routes.scan_exports",
    "get_skill_audit": "agent_bom.api.routes.scan_exports",
    "issue_severity_counts": "agent_bom.api.finding_snapshot_read",
    "current_findings_snapshot": "agent_bom.api.finding_snapshot_read",
    "_coerce_bulk_severity": "agent_bom.api.bulk_findings_ingest",
    "_dataclass_to_dict": "agent_bom.api.ai_scan_runtime",
    "_freshness_bucket": "agent_bom.api.finding_list_helpers",
    "_redact_scan_result_for_response": "agent_bom.api.scan_job_views",
    "_sanitize_api_path": "agent_bom.api.scan_path_jail",
    "correlation_cohort_parent_job_id": "agent_bom.api.scan_cohorts",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
