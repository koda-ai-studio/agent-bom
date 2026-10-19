"""Durable connection scan dispatch and queue lifecycle."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from agent_bom.api.audit_log import log_action
from agent_bom.api.connection_request_validation import CloudConnectionScanAccepted, _now
from agent_bom.api.connection_scan_aws import _run_aws_connection_scan
from agent_bom.api.connection_scan_database import _run_database_connection_scan
from agent_bom.api.connection_scan_providers import (
    _run_azure_connection_scan,
    _run_databricks_connection_scan,
    _run_gcp_connection_scan,
    _run_snowflake_connection_scan,
)
from agent_bom.api.connection_scan_reports import _logger, _mark_connection, _safe_connection_detail
from agent_bom.api.connection_store import STATUS_ACTIVE, STATUS_ERROR, CloudConnectionRecord, get_connection_store
from agent_bom.api.tenant_quota import tenant_quota_guard
from agent_bom.security import sanitize_error, sanitize_text

_SCAN_RUNNERS: dict[str, Callable[..., dict[str, Any]]] = {
    "aws": _run_aws_connection_scan,
    "azure": _run_azure_connection_scan,
    "gcp": _run_gcp_connection_scan,
    "snowflake": _run_snowflake_connection_scan,
    "database": _run_database_connection_scan,
    "databricks": _run_databricks_connection_scan,
}

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


def _run_connection_scan(
    record: CloudConnectionRecord,
    tenant_id: str,
    *,
    queued_job: ScanJob | None = None,
) -> dict[str, Any]:
    """Dispatch a brokered read-only scan by provider.

    Raises ``ValueError`` for an unknown provider (the route validates the
    provider on create, so this is a defensive guard).
    """
    runner = _SCAN_RUNNERS.get((record.provider or "").strip().lower())
    if runner is None:
        raise ValueError(f"Unsupported provider '{record.provider}'.")
    if queued_job is None:
        return runner(record, tenant_id)
    return runner(record, tenant_id, queued_job=queued_job)


_QUEUED_CONNECTION_SOURCE_PREFIX = "cloud-connection:"


def is_queued_connection_scan(job: ScanJob) -> bool:
    """Return whether a normal scan job carries connection-scan provenance."""
    return str(job.source_id or "").startswith(_QUEUED_CONNECTION_SOURCE_PREFIX)


def execute_queued_connection_scan(job: ScanJob) -> dict[str, Any]:
    """Execute one durable cloud-connection job under the worker's tenant.

    The job itself is the restart/retry identity. A reclaimed delivery therefore
    writes the same scan row and graph snapshot instead of creating a second scan
    artifact. Provider access remains read-only; only agent-bom evidence and the
    connection's lifecycle metadata are updated.
    """
    from agent_bom.api.models import JobStatus

    source_id = str(job.source_id or "")
    if not source_id.startswith(_QUEUED_CONNECTION_SOURCE_PREFIX):
        raise RuntimeError("Queued cloud connection scan is missing its connection reference.")
    connection_id = source_id.removeprefix(_QUEUED_CONNECTION_SOURCE_PREFIX).strip()
    tenant_id = str(job.tenant_id or "default")
    record = get_connection_store().get(tenant_id, connection_id)
    if record is None:
        raise RuntimeError("Cloud connection is no longer available for this tenant.")
    if record.auth_params.get("demo") is True:
        raise RuntimeError("Showcase connections cannot run connection scans.")
    # Revalidate the current durable row at worker time.  An operator may have
    # changed the connection after the request was accepted, and a row created
    # before trial mode was enabled must never bypass the live AWS/account/region
    # envelope merely because it is already queued.
    from agent_bom.api.managed_trial import enforce_stored_connection_envelope

    enforce_stored_connection_envelope(record)

    actor = str(job.triggered_by or "system")
    try:
        summary = _run_connection_scan(record, tenant_id, queued_job=job)
    except Exception as exc:  # noqa: BLE001 - durable worker failure boundary
        detail = _safe_connection_detail(exc)
        _mark_connection(record, status=STATUS_ERROR, status_detail=detail)
        _logger.error(
            "Cloud connection scan job failed connection=%s job=%s: %s",
            record.id,
            job.job_id,
            sanitize_text(sanitize_error(exc, generic=True)),
        )
        log_action(
            "cloud_connection.scan",
            actor=actor,
            resource=f"cloud-connection/{record.id}",
            tenant_id=tenant_id,
            provider=record.provider,
            outcome="failure",
            job_id=job.job_id,
        )
        # The outer scan worker owns the terminal job transition. Raise only the
        # curated/sanitized detail so provider SDK text and credentials never
        # enter the durable job error or progress fields.
        raise RuntimeError(detail) from None

    from agent_bom.cloud.capability_probe import scan_verified_capabilities

    _mark_connection(
        record,
        status=STATUS_ACTIVE,
        status_detail="",
        capability_probe_status="verified",
        verified_capabilities=list(scan_verified_capabilities(record.provider)),
        last_scan_at=_now(),
        last_scan_id=job.job_id,
    )
    log_action(
        "cloud_connection.scan",
        actor=actor,
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
        outcome="success",
        scan_id=job.job_id,
        job_id=job.job_id,
    )
    job.progress.append(f"Cloud connection scan completed for provider {record.provider}")
    job.status = JobStatus.DONE
    return summary


def _accepted_connection_scan(job: ScanJob, record: CloudConnectionRecord) -> CloudConnectionScanAccepted:
    """Stable, non-secret response returned for a queued connection scan."""
    return CloudConnectionScanAccepted(
        connection_id=record.id,
        tenant_id=record.tenant_id,
        provider=record.provider,
        job_id=job.job_id,
    )


def queue_connection_scan_record(record: CloudConnectionRecord, *, actor: str) -> ScanJob:
    """Reserve and dispatch one durable connection scan outside an HTTP route.

    Create-time and scheduler triggers use this entry point so they share the
    same quota, credit, worker, and persisted job lifecycle as manual scans.
    Trial mode disables both callers, but this still revalidates the durable row
    to fail closed if an operator toggles policy during a queued handoff.
    """

    from agent_bom.api.managed_trial import enforce_stored_connection_envelope
    from agent_bom.api.models import ScanRequest
    from agent_bom.api.scan_job_dispatch import dispatch_scan_job
    from agent_bom.api.scan_job_submission import enqueue_scan_job
    from agent_bom.api.stores import _get_store, _jobs_pop
    from agent_bom.api.tenant_quota import (
        consume_managed_trial_scan_credit,
        enforce_active_scan_quota,
        enforce_retained_jobs_quota,
    )

    enforce_stored_connection_envelope(record)
    job: ScanJob | None = None
    with tenant_quota_guard(
        record.tenant_id,
        lambda: enforce_active_scan_quota(record.tenant_id),
        lambda: enforce_retained_jobs_quota(record.tenant_id),
    ):
        try:
            job = enqueue_scan_job(
                tenant_id=record.tenant_id,
                triggered_by=actor,
                request_body=ScanRequest(),
                source_id=f"{_QUEUED_CONNECTION_SOURCE_PREFIX}{record.id}",
                quota_guarded=True,
                dispatch=False,
            )
            consume_managed_trial_scan_credit(record.tenant_id)
        except Exception:
            if job is not None:
                _get_store().delete(job.job_id, tenant_id=record.tenant_id)
                _jobs_pop(job.job_id, tenant_id=job.tenant_id)
            raise
    assert job is not None
    dispatch_scan_job(job)
    return job
