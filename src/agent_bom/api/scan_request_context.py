"""Scan request tenant, path and job access boundaries."""

from __future__ import annotations

import logging
from functools import partial
from typing import Any, cast

import anyio.to_thread
from fastapi import HTTPException, Request

from agent_bom.api.hub_ingest import hub_ingest_store_writes, hub_store_call
from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.scan_batches import refresh_batch_parent
from agent_bom.api.scan_job_views import _job_response_payload
from agent_bom.api.scan_path_jail import _api_scan_path_or_400
from agent_bom.api.stores import _get_store, _jobs_get, _jobs_is_compacted
from agent_bom.api.tenancy import require_request_tenant_id

_logger = logging.getLogger("agent_bom.api.routes.scan")


def _require_json_content_type(request: Request) -> None:
    """Reject ambiguous bulk-ingest bodies before accepting caller data."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json" and not media_type.endswith("+json"):
        raise HTTPException(status_code=422, detail="Content-Type must be application/json")


_hub_store_call = hub_store_call


_bulk_ingest_store_writes = hub_ingest_store_writes


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
