"""CIS Foundations Benchmark check listing and trend routes."""

from __future__ import annotations

import logging
from typing import Annotated

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.cis_graph_checks import NOT_EVALUATED, GraphCisState, merge_cis_rows_with_graph, read_graph_cis_state
from agent_bom.api.finding_read_context import read_once
from agent_bom.api.models import JobStatus
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.compliance import CisChecksResponse, CisTrendsResponse
from agent_bom.api.routes.compliance_routes.common import _tenant_id, _tenant_jobs
from agent_bom.api.routes.compliance_routes.evidence import (
    _cis_check_rows_from_jobs,
    _cis_trend_buckets_from_jobs,
    _coerce_cis_row,
    _latest_cis_rows_from_jobs,
    _normalize_csv_filter,
    filter_cis_rows,
)
from agent_bom.api.stores import _get_analytics_store, _get_graph_store, _get_store
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.security import sanitize_text

router = APIRouter()
_logger = logging.getLogger(__name__)


@router.get("/cis/checks", **documented(CisChecksResponse), tags=["compliance"])
async def list_cis_benchmark_checks(
    request: Request,
    cloud: str | None = None,
    status: str | None = None,
    priority: int | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: int = 0,
) -> dict:
    """List tenant-scoped CIS benchmark checks with indexed filters where available.

    The synchronous store reads (columnar/analytics queries plus the in-memory
    scan-job fallback) run in a worker thread under adaptive backpressure so a
    deep listing cannot block the event loop; under saturation the endpoint
    sheds with ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_list_cis_benchmark_checks_impl, request, cloud, status, priority, limit, offset)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _list_cis_benchmark_checks_impl(
    request: Request,
    cloud: str | None,
    status: str | None,
    priority: int | None,
    limit: int,
    offset: int,
) -> dict:
    tenant_id = _tenant_id(request)
    safe_limit = max(1, min(int(limit), 500))
    safe_offset = max(0, int(offset))
    cloud_filter = _normalize_csv_filter(cloud)
    status_filter = _normalize_csv_filter(status)
    if priority is not None and priority < 0:
        raise HTTPException(status_code=400, detail="priority must be >= 0")

    cis_graph = read_graph_cis_state(_get_graph_store(), tenant_id)
    if cis_graph.checks or NOT_EVALUATED in status_filter:
        stored, source = _stored_cis_rows(request, tenant_id)
        rows = filter_cis_rows(merge_cis_rows_with_graph(stored, cis_graph), cloud_filter, status_filter, priority)
        checks = [_coerce_cis_row(row) for row in rows[safe_offset : safe_offset + safe_limit]]
        return {"checks": checks, "count": len(rows), "source": f"{source}+graph" if cis_graph.checks else source}

    job_store = _get_store()
    store_query = getattr(job_store, "query_cis_benchmark_checks", None)
    if callable(store_query) and len(cloud_filter) <= 1 and len(status_filter) <= 1:
        rows = store_query(
            tenant_id,
            cloud=next(iter(cloud_filter), None),
            status=next(iter(status_filter), None),
            priority=priority,
            limit=safe_limit,
            offset=safe_offset,
        )
        if rows:
            return {"checks": [_coerce_cis_row(row) for row in rows], "count": len(rows), "source": "columnar"}

    analytics_store = _get_analytics_store()
    query_fn = getattr(analytics_store, "query_cis_benchmark_checks", None)
    if callable(query_fn) and len(cloud_filter) <= 1 and len(status_filter) <= 1:
        try:
            rows = query_fn(
                cloud=next(iter(cloud_filter), None),
                status=next(iter(status_filter), None),
                priority=priority,
                limit=safe_limit,
                offset=safe_offset,
                tenant_id=tenant_id,
            )
            if rows:
                return {"checks": [_coerce_cis_row(row) for row in rows], "count": len(rows), "source": "analytics"}
        except Exception:
            pass

    return _cis_check_rows_from_jobs(_tenant_jobs(request), cloud_filter, status_filter, priority, safe_limit, safe_offset)


def current_cis_graph(request: Request, scan_id: str | None = None, tenant_jobs: list | None = None) -> GraphCisState:
    """The current graph's CIS results; a read pinned to a historical scan never takes them.

    ``tenant_jobs`` is the caller's job snapshot. The current-estate graph reads
    the tenant's completed jobs through the request-scoped ``("jobs", tenant)``
    read, so seeding it keeps the verdict and its CIS evidence on one snapshot.
    """
    if scan_id:
        return GraphCisState.empty()
    tenant_id = _tenant_id(request)
    if tenant_jobs is not None:
        read_once(("jobs", tenant_id), lambda: [job for job in tenant_jobs if job.status == JobStatus.DONE and job.result])
    return read_graph_cis_state(_get_graph_store(), tenant_id)


def _stored_cis_rows(request: Request, tenant_id: str) -> tuple[list[dict], str]:
    """Every latest stored CIS row, unfiltered, from the first store that holds them."""
    store_query = getattr(_get_store(), "query_cis_benchmark_checks", None)
    if callable(store_query):
        rows = store_query(tenant_id, cloud=None, status=None, priority=None, limit=500, offset=0)
        if rows:
            return list(rows), "columnar"
    query_fn = getattr(_get_analytics_store(), "query_cis_benchmark_checks", None)
    if callable(query_fn):
        try:
            rows = query_fn(cloud=None, status=None, priority=None, limit=500, offset=0, tenant_id=tenant_id)
            if rows:
                return list(rows), "analytics"
        except Exception as exc:  # broad-except: an analytics outage falls back to the scan jobs
            _logger.warning("Analytics CIS read failed; using scan jobs: %s", sanitize_text(exc))
    return _latest_cis_rows_from_jobs(_tenant_jobs(request)), "scan_jobs"


# ─── CIS Benchmark Trend / Drilldown (#1832) ──────────────────────────────


@router.get("/cis/trends", **documented(CisTrendsResponse), tags=["compliance"], deprecated=True)
async def cis_benchmark_trends(
    request: Request,
    days: int = 30,
    bucket: str = "day",
    cloud: str | None = None,
    section: str | None = None,
    status: str | None = None,
    severity: str | None = None,
) -> dict:
    """Time-bucketed CIS finding counts for trend / drilldown surfaces.

    Resolves to the columnar store (Postgres ``cis_benchmark_checks`` →
    ClickHouse) when available; otherwise reconstructs the aggregation
    in-memory from the tenant's recent scan results so single-node and
    SQLite-only deployments still return data.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).

    Query parameters:
    - ``days`` (1–366, default 30): rolling window size.
    - ``bucket`` (``hour`` | ``day`` | ``week``, default ``day``): bucket
      width. Anything else falls back to ``day``.
    - ``cloud`` / ``section`` / ``status`` / ``severity``: optional
      single-value filters narrowing the slice before aggregation.

    The synchronous aggregation (columnar/analytics stores plus the in-memory
    scan-job fallback) runs in a worker thread under adaptive backpressure so
    it never blocks the event loop; under saturation the endpoint sheds with
    ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_cis_benchmark_trends_impl, request, days, bucket, cloud, section, status, severity)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _cis_benchmark_trends_impl(
    request: Request,
    days: int,
    bucket: str,
    cloud: str | None,
    section: str | None,
    status: str | None,
    severity: str | None,
) -> dict:
    tenant_id = _tenant_id(request)
    bucket_unit = bucket if bucket in {"hour", "day", "week"} else "day"
    days_clamped = max(1, min(int(days), 366))

    job_store = _get_store()
    aggregate_fn = getattr(job_store, "aggregate_cis_benchmark_checks", None)
    if callable(aggregate_fn):
        try:
            buckets = aggregate_fn(
                tenant_id,
                days=days_clamped,
                cloud=cloud,
                section=section,
                status=status,
                severity=severity,
                bucket=bucket_unit,
            )
            if buckets:
                return {
                    "buckets": buckets,
                    "count": len(buckets),
                    "source": "columnar",
                    "bucket": bucket_unit,
                    "days": days_clamped,
                }
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Postgres CIS aggregation failed; trying analytics store: %s", sanitize_text(exc))

    analytics_store = _get_analytics_store()
    analytics_aggregate = getattr(analytics_store, "aggregate_cis_benchmark_checks", None)
    if callable(analytics_aggregate):
        try:
            buckets = analytics_aggregate(
                days=days_clamped,
                cloud=cloud,
                section=section,
                status=status,
                severity=severity,
                bucket=bucket_unit,
                tenant_id=tenant_id,
            )
            if buckets:
                return {
                    "buckets": buckets,
                    "count": len(buckets),
                    "source": "analytics",
                    "bucket": bucket_unit,
                    "days": days_clamped,
                }
        except Exception as exc:  # noqa: BLE001
            _logger.warning("ClickHouse CIS aggregation failed: %s", sanitize_text(exc))

    # In-memory fallback: aggregate the tenant's recent scan results
    # locally so even single-node and SQLite-only deployments answer.
    return _cis_trend_buckets_from_jobs(_tenant_jobs(request), days_clamped, bucket_unit, cloud, section, status, severity)
