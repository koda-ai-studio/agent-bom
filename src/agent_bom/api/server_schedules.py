"""Resolve scheduled scans to tenant-scoped canonical requests."""

from __future__ import annotations

from typing import Any

from agent_bom.api.models import ScanRequest
from agent_bom.api.scan_batches import scan_request_targets
from agent_bom.api.stores import _get_schedule_store, _get_source_store


def _enqueue_scheduled_scan(
    scan_config: dict[str, Any],
    *,
    schedule_id: str | None = None,
    tenant_id: str | None = None,
    scheduled_for: str | None = None,
) -> str:
    """Resolve a schedule to one canonical request and enqueue it durably."""

    resolved_tenant_id = tenant_id or scan_config.get("tenant_id", "default")
    resolved_tenant_id = str(resolved_tenant_id or "default")
    source_id = str(scan_config.get("source_id") or "").strip()
    raw_source_ids = scan_config.get("source_ids")

    from agent_bom.api.routes.scan import enqueue_scan_job

    if raw_source_ids is not None:
        return _enqueue_source_cohort(scan_config, raw_source_ids, source_id, resolved_tenant_id, schedule_id, scheduled_for)
    if source_id:
        return _enqueue_source(source_id, resolved_tenant_id, schedule_id)

    request_payload = {key: value for key, value in scan_config.items() if key in ScanRequest.model_fields}
    legacy_path = scan_config.get("path")
    if isinstance(legacy_path, str) and legacy_path and not request_payload.get("agent_projects"):
        request_payload["agent_projects"] = [legacy_path]
    request_body = ScanRequest(**request_payload)
    if request_body.discover_host:
        from agent_bom.api.scan_boundary import require_host_discovery_for_tenant

        require_host_discovery_for_tenant(resolved_tenant_id)
    job = enqueue_scan_job(
        tenant_id=resolved_tenant_id,
        triggered_by="scheduler",
        request_body=request_body,
        schedule_id=schedule_id,
    )
    return job.job_id


def _enqueue_source_cohort(
    scan_config: dict[str, Any],
    raw_source_ids: Any,
    source_id: str,
    resolved_tenant_id: str,
    schedule_id: str | None,
    scheduled_for: str | None,
) -> str:
    from agent_bom.api.routes.scan import correlation_cohort_id, enqueue_correlation_cohort

    if source_id or not isinstance(raw_source_ids, list):
        raise RuntimeError("Scheduled correlation cohort requires an exact source_ids list without source_id")
    source_ids = sorted(str(value).strip() for value in raw_source_ids)
    if not 2 <= len(source_ids) <= 32 or any(not value for value in source_ids) or len(set(source_ids)) != len(source_ids):
        raise RuntimeError("Scheduled correlation cohort requires 2-32 distinct source ids")
    if not schedule_id or not scheduled_for:
        raise RuntimeError("Scheduled correlation cohort requires an exact schedule occurrence")
    max_age_hours = scan_config.get("max_age_hours", 168)
    if isinstance(max_age_hours, bool) or not isinstance(max_age_hours, int) or not 1 <= max_age_hours <= 8760:
        raise RuntimeError("Scheduled correlation max_age_hours must be between 1 and 8760")

    from agent_bom.api.routes.sources import _request_for_source, _validate_credential_ref_for_tenant
    from agent_bom.api.tenant_quota import (
        enforce_active_scan_quota,
        enforce_retained_jobs_quota,
        tenant_quota_guard,
    )

    with tenant_quota_guard(resolved_tenant_id):
        schedule = _get_schedule_store().get(schedule_id, tenant_id=resolved_tenant_id)
        scheduled_source_ids = (
            sorted(str(value).strip() for value in schedule.scan_config.get("source_ids", []))
            if schedule is not None and isinstance(schedule.scan_config.get("source_ids"), list)
            else []
        )
        scheduled_max_age = schedule.scan_config.get("max_age_hours", 168) if schedule is not None else None
        if schedule is None or not schedule.enabled or scheduled_source_ids != source_ids or scheduled_max_age != max_age_hours:
            raise RuntimeError("Scheduled correlation cohort is no longer active in this tenant")

        members: list[tuple[str, ScanRequest]] = []
        sources = []
        for member_source_id in source_ids:
            source = _get_source_store().get(member_source_id, tenant_id=resolved_tenant_id)
            if source is None or source.tenant_id != resolved_tenant_id or not source.enabled:
                raise RuntimeError("Scheduled correlation source is unavailable in this tenant")
            _validate_credential_ref_for_tenant(resolved_tenant_id, source)
            request_body = _request_for_source(source)
            if len(scan_request_targets(request_body)) != 1:
                raise RuntimeError("Scheduled correlation source must resolve to exactly one scan target")
            members.append((member_source_id, request_body))
            sources.append(source)

        attempted_jobs = len(members) + 1
        enforce_active_scan_quota(resolved_tenant_id, attempted=attempted_jobs)
        enforce_retained_jobs_quota(resolved_tenant_id, attempted=attempted_jobs)
        cohort_id = correlation_cohort_id(
            tenant_id=resolved_tenant_id,
            idempotency_key=f"schedule:{schedule_id}:{scheduled_for}",
        )
        parent = enqueue_correlation_cohort(
            tenant_id=resolved_tenant_id,
            triggered_by=f"scheduler:source-cohort:{schedule_id}",
            correlation_cohort_id=cohort_id,
            source_requests=members,
            max_age_hours=max_age_hours,
            schedule_id=schedule_id,
            quota_guarded=True,
        )
        from agent_bom.api.pipeline import _now

        run_at = _now()
        for source, child_job_id in zip(sources, parent.child_job_ids, strict=True):
            source.last_run_at = run_at
            source.last_run_status = "pending"
            source.last_job_id = child_job_id
            source.updated_at = run_at
            _get_source_store().put(source, tenant_id=resolved_tenant_id)
    return parent.job_id


def _enqueue_source(source_id: str, resolved_tenant_id: str, schedule_id: str | None) -> str:
    from agent_bom.api.routes.scan import enqueue_scan_job
    from agent_bom.api.routes.sources import _request_for_source, _validate_credential_ref_for_tenant
    from agent_bom.api.tenant_quota import (
        enforce_active_scan_quota,
        enforce_retained_jobs_quota,
        tenant_quota_guard,
    )

    with tenant_quota_guard(resolved_tenant_id):
        if schedule_id:
            schedule = _get_schedule_store().get(schedule_id, tenant_id=resolved_tenant_id)
            scheduled_source_id = str(schedule.scan_config.get("source_id") or "") if schedule is not None else ""
            if schedule is None or not schedule.enabled or scheduled_source_id != source_id:
                raise RuntimeError("Scheduled source is no longer active in this tenant")
        source = _get_source_store().get(source_id, tenant_id=resolved_tenant_id)
        if source is None or source.tenant_id != resolved_tenant_id:
            raise RuntimeError("Scheduled source is unavailable in this tenant")
        if not source.enabled:
            raise RuntimeError("Scheduled source is disabled")
        _validate_credential_ref_for_tenant(resolved_tenant_id, source)
        request_body = _request_for_source(source)
        target_count = len(scan_request_targets(request_body))
        attempted_jobs = target_count + 1 if target_count > 1 else 1
        enforce_active_scan_quota(resolved_tenant_id, attempted=attempted_jobs)
        enforce_retained_jobs_quota(resolved_tenant_id, attempted=attempted_jobs)
        job = enqueue_scan_job(
            tenant_id=resolved_tenant_id,
            triggered_by=f"scheduler:source:{source_id}",
            request_body=request_body,
            source_id=source_id,
            schedule_id=schedule_id,
            quota_guarded=True,
        )
        from agent_bom.api.pipeline import _now

        source.last_run_at = _now()
        source.last_run_status = job.status.value
        source.last_job_id = job.job_id
        source.updated_at = _now()
        _get_source_store().put(source, tenant_id=resolved_tenant_id)
    return job.job_id
