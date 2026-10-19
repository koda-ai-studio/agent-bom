"""Per-tenant cloud connections plane — CRUD over read-only cloud connections.

A *connection* is a stored, encrypted, tenant-scoped record of how the control
plane reaches a customer's cloud account in read-only mode: the role it assumes
plus the encrypted ``ExternalId`` (or provider equivalent) the credential broker
presents. These endpoints manage that record; the secret is encrypted at rest
and is **never** returned in any response.

Every endpoint enforces ``require_request_tenant_id`` plus RBAC via the shared
dependency. **Reads** (list/get) require the ``read`` permission (admin, analyst,
viewer). **Mutations** (create, update schedule, delete, test, scan) require
``scan`` (admin, analyst). Under-privileged roles are rejected with 403. Reads
and deletes are tenant-scoped: a tenant can only see or remove its own connections.

Endpoints:
    POST   /v1/cloud/connections          create a connection (encrypts the secret)
    GET    /v1/cloud/connections          list this tenant's connections
    GET    /v1/cloud/connections/{id}     one connection (non-secret metadata)
    DELETE /v1/cloud/connections/{id}     remove a connection
    POST   /v1/cloud/connections/{id}/test  validate brokered read-only auth
    POST   /v1/cloud/connections/{id}/scan  launch a read-only scan via the broker

The ``/scan`` endpoint brokers the stored connection into a short-lived read-only
cloud session / credential / connection (AWS ``sts:AssumeRole`` with the decrypted
ExternalId; Azure ``ClientSecretCredential``; GCP read-only service-account
credentials; Snowflake key-pair connection) and runs the **same** inventory + CIS
discovery the sibling ``cloud`` routes use, against that session. Results persist
through the existing scan/graph stores — no parallel persistence path — and the
connection's lifecycle status is updated (``active`` + ``last_scan_at`` on
success, ``error`` + ``status_detail`` on failure, never carrying a secret).
Databricks also uses a scoped workspace client for inventory and vendor
security checks. A connection may also carry a ``scan_interval_minutes`` so the background scheduler
(:mod:`agent_bom.api.connection_scheduler`) re-runs this same scan path when due."""

from __future__ import annotations

import uuid
from importlib import import_module
from typing import TYPE_CHECKING, Any

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.audit_log import log_action
from agent_bom.api.cloud_connection_models import CloudConnectionCreate, CloudConnectionUpdate
from agent_bom.api.connection_crypto import ConnectionSecretError, connections_key_configured, encrypt_secret
from agent_bom.api.connection_request_validation import (
    CloudConnectionScanAccepted,
    _actor,
    _now,
    _reject_showcase_connection,
    _require_connection,
    _tenant,
    _validate_auth_params,
    _validate_inventory_scope,
    _validate_regions,
    _validate_scan_interval,
    _validate_scan_mode,
)
from agent_bom.api.connection_scan_reports import (
    _logger,
    _mark_connection,
    _safe_connection_detail,
    _scan_audit_metadata,
    _test_connection_broker,
)
from agent_bom.api.connection_scan_worker import (
    _QUEUED_CONNECTION_SOURCE_PREFIX,
    _SCAN_RUNNERS,
    _accepted_connection_scan,
    queue_connection_scan_record,
)
from agent_bom.api.connection_store import (
    STATUS_ACTIVE,
    STATUS_ERROR,
    STATUS_PENDING,
    SUPPORTED_PROVIDERS,
    CloudConnectionRecord,
    get_connection_store,
)
from agent_bom.api.read_models import CloudConnectionsResponse, documented
from agent_bom.api.read_models import runtime_estate_a as rt
from agent_bom.api.tenant_quota import enforce_cloud_connection_quota, tenant_quota_guard
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.cloud.event_ingest import CloudChangeEvent, dispatch_change_event
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error, sanitize_text

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


router = APIRouter(tags=["cloud-connections"])


_READ_DEP = require_authenticated_permission("read")


_SCAN_DEP = require_authenticated_permission("scan")


@router.post("/cloud/connections", status_code=201)
def create_connection(request: Request, body: CloudConnectionCreate, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Create a read-only cloud connection for the authenticated tenant.

    The ``external_id`` secret is encrypted at rest before persistence and is
    never echoed back. If no encryption key is configured the request fails
    closed with 503 rather than storing the secret in plaintext. When
    ``auto_scan_on_create`` is true (the default), the same durable brokered
    scan path as ``POST …/scan`` is queued after persistence; a queue failure
    marks the connection ``error`` with a sanitized detail but does not roll
    back the create.
    """
    tenant_id = _tenant(request)
    provider = body.provider.strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider '{body.provider}'. Use one of: {', '.join(SUPPORTED_PROVIDERS)}.",
        )

    regions = _validate_regions(body.regions)
    scan_interval_minutes = _validate_scan_interval(body.scan_interval_minutes)
    auth_params = _validate_auth_params(provider, body.auth_params)
    inventory_scope = _validate_inventory_scope(body.inventory_scope, auth_params=auth_params)
    scan_mode = _validate_scan_mode(body.scan_mode)
    auto_scan_on_create = bool(body.auto_scan_on_create)

    from agent_bom.api.managed_trial import enforce_connection_envelope, managed_trial_enabled

    enforce_connection_envelope(
        provider=provider,
        regions=regions,
        inventory_scope=inventory_scope,
        scan_mode=scan_mode,
        scan_interval_minutes=scan_interval_minutes,
    )
    if managed_trial_enabled():
        auto_scan_on_create = False

    from agent_bom.cloud.connection_broker import ConnectionBrokerError
    from agent_bom.cloud.connection_workload import resolve_binding, workload_mode

    try:
        mode = workload_mode(provider, auth_params)
        if mode:
            if body.external_id:
                raise ConnectionBrokerError("Workload connections do not accept stored credentials.")
            resolve_binding(
                CloudConnectionRecord(
                    id="pending",
                    tenant_id=tenant_id,
                    provider=provider,
                    display_name=body.display_name,
                    role_ref=body.role_ref.strip(),
                    external_id_encrypted="",
                    auth_params=auth_params,
                    inventory_scope=inventory_scope,
                )
            )
            external_id_encrypted = ""
        else:
            if not body.external_id.strip():
                raise HTTPException(status_code=400, detail="A credential is required for this connection authentication mode.")
            if not connections_key_configured():
                raise HTTPException(status_code=503, detail="Connection secret encryption is not configured; refusing to store a secret.")
            external_id_encrypted = encrypt_secret(body.external_id.strip())
    except ConnectionBrokerError as exc:
        raise HTTPException(status_code=400, detail="Workload connection configuration is invalid or unavailable.") from exc
    except ConnectionSecretError as exc:
        _logger.warning("Connection secret encryption unavailable")
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc

    now = _now()
    record = CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        provider=provider,
        display_name=body.display_name.strip(),
        role_ref=body.role_ref.strip(),
        external_id_encrypted=external_id_encrypted,
        regions=regions,
        status=STATUS_PENDING,
        status_detail="",
        created_at=now,
        updated_at=now,
        last_scan_at=None,
        scan_interval_minutes=scan_interval_minutes,
        auth_params=auth_params,
        inventory_scope=inventory_scope,
        scan_mode=scan_mode,
        auto_scan_on_create=auto_scan_on_create,
    )
    with tenant_quota_guard(
        tenant_id,
        lambda: enforce_cloud_connection_quota(tenant_id, provider),
    ):
        get_connection_store().put(record)
    log_action(
        "cloud_connection.create",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
    )

    # Default auto_scan_on_create=true: reserve the same durable job used by the
    # manual and scheduler paths.  Provider I/O never runs in the API request.
    # Managed-trial mode forces this flag off before persistence.
    if auto_scan_on_create:
        actor = _actor(request)
        try:
            job = queue_connection_scan_record(record, actor=actor)
            _mark_connection(
                record,
                status=STATUS_PENDING,
                status_detail="",
                last_scan_id=job.job_id,
            )
            log_action(
                "cloud_connection.scan",
                actor=actor,
                resource=f"cloud-connection/{record.id}",
                tenant_id=tenant_id,
                provider=record.provider,
                outcome="accepted",
                job_id=job.job_id,
            )
        except Exception as exc:  # noqa: BLE001 - durable dispatch boundary
            detail = "Connection created, but its initial scan could not be queued."
            _mark_connection(record, status=STATUS_ERROR, status_detail=detail)
            _logger.error(
                "Cloud connection scan-on-create enqueue failed connection=%s: %s",
                record.id,
                sanitize_text(sanitize_error(exc, generic=True)),
            )

    return record.to_public_dict()


@router.get("/cloud/connections", **documented(CloudConnectionsResponse))
def list_connections(request: Request, _role: Any = _READ_DEP) -> dict[str, Any]:
    """List the authenticated tenant's connections (non-secret metadata only)."""
    from agent_bom.api.connection_scheduler import connections_scheduler_enabled
    from agent_bom.cloud.connection_workload import supported_workload_modes

    tenant_id = _tenant(request)
    records = get_connection_store().list_for_tenant(tenant_id)
    return {
        "schema_version": "cloud.connections.v1",
        "tenant_id": tenant_id,
        "connections": [r.to_public_dict() for r in records],
        "count": len(records),
        # Packaging honesty for the UI schedule banner: intervals alone do not
        # run unless the control-plane scheduler process is enabled.
        "connections_scheduler_enabled": connections_scheduler_enabled(),
        "workload_auth_modes": supported_workload_modes(),
    }


class CloudChangeEventIngestItem(BaseModel):
    """One normalized posture-change event (event-collector → control plane)."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    account: str = Field(min_length=1, max_length=128)
    region: str = Field(default="", max_length=64)
    resource_type: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=512)
    action: str = Field(min_length=1, max_length=256)
    arn: str = Field(default="", max_length=2048)
    raw: dict[str, Any] = Field(default_factory=dict)


class CloudConnectionsEventsIngestRequest(BaseModel):
    """Batch body for ``POST /v1/cloud/connections/events/ingest``."""

    model_config = ConfigDict(extra="forbid")

    events: list[CloudChangeEventIngestItem] = Field(min_length=1, max_length=100)


def _account_from_role_ref(role_ref: str) -> str:
    """Extract the AWS account id from a connection ``role_ref`` ARN."""
    parts = (role_ref or "").split(":")
    return parts[4] if len(parts) > 4 else ""


def _match_connection_for_event(
    tenant_id: str,
    provider: str,
    account: str,
) -> CloudConnectionRecord | None:
    """Return the tenant connection bound to *provider* + *account*, if any."""
    provider_l = (provider or "").strip().lower()
    account_s = (account or "").strip()
    if not provider_l or not account_s:
        return None
    for record in get_connection_store().list_for_tenant(tenant_id):
        if (record.provider or "").strip().lower() != provider_l:
            continue
        if _account_from_role_ref(record.role_ref) == account_s:
            return record
    return None


@router.post("/cloud/connections/events/ingest")
async def ingest_connection_events(
    request: Request,
    body: CloudConnectionsEventsIngestRequest,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Accept a batch of normalized cloud change events from the event collector.

    Auth-by-default (``scan`` permission). Each event is matched to a tenant
    connection by provider + account (from ``role_ref``); unmatched accounts are
    skipped fail-closed (no confused-deputy scan). Heavy dispatch runs off the
    event loop. Errors are sanitized — never returned raw.
    """
    from agent_bom.api.managed_trial import require_managed_trial_feature

    require_managed_trial_feature("Continuous connection event ingest")
    tenant_id = _tenant(request)
    results: list[dict[str, Any]] = []
    dispatched = 0
    skipped = 0

    def _process() -> None:
        nonlocal dispatched, skipped
        for item in body.events:
            record = _match_connection_for_event(tenant_id, item.provider, item.account)
            if record is None:
                skipped += 1
                results.append(
                    {
                        "account": item.account,
                        "provider": item.provider,
                        "status": "skipped",
                        "detail": "no matching connection for account",
                    }
                )
                continue
            event = CloudChangeEvent(
                provider=item.provider.strip().lower(),
                account=item.account.strip(),
                region=(item.region or "").strip(),
                resource_type=item.resource_type.strip().lower(),
                resource_id=item.resource_id.strip(),
                action=item.action.strip(),
                arn=(item.arn or "").strip(),
                raw=item.raw if isinstance(item.raw, dict) else {},
            )
            try:
                summary = dispatch_change_event(event, record, tenant_id=tenant_id)
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                _logger.warning(
                    "Connection event ingest dispatch failed for connection %s: %s",
                    record.id,
                    sanitize_text(sanitize_error(exc, generic=True)),
                )
                results.append(
                    {
                        "account": item.account,
                        "provider": item.provider,
                        "connection_id": record.id,
                        "status": "skipped",
                        "detail": sanitize_error(exc, generic=True),
                    }
                )
                continue
            if summary is None:
                skipped += 1
                results.append(
                    {
                        "account": item.account,
                        "provider": item.provider,
                        "connection_id": record.id,
                        "status": "skipped",
                        "detail": "dispatch declined (account/type guard)",
                    }
                )
                continue
            dispatched += 1
            results.append(
                {
                    "account": item.account,
                    "provider": item.provider,
                    "connection_id": record.id,
                    "status": "dispatched",
                    "detail": "",
                }
            )

    try:
        async with adaptive_backpressure("connection_events_ingest"):
            await anyio.to_thread.run_sync(_process)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _logger.error("Connection events ingest failed")
        raise HTTPException(
            status_code=500,
            detail=sanitize_error(exc, generic=True),
        ) from exc

    log_action(
        "cloud_connection.events_ingest",
        actor=_actor(request),
        resource="cloud-connection/events",
        tenant_id=tenant_id,
        outcome="success",
        accepted=len(body.events),
        dispatched=dispatched,
        skipped=skipped,
    )
    return {
        "schema_version": "cloud.connections.events.ingest.v1",
        "tenant_id": tenant_id,
        "accepted": len(body.events),
        "dispatched": dispatched,
        "skipped": skipped,
        "results": results,
    }


@router.get("/cloud/connections/{connection_id}", **documented(rt.CloudConnectionDetailResponse))
def get_connection(request: Request, connection_id: str, _role: Any = _READ_DEP) -> dict[str, Any]:
    """Return one connection's non-secret metadata (tenant-scoped)."""
    return _require_connection(request, connection_id).to_public_dict()


@router.patch("/cloud/connections/{connection_id}")
def update_connection(
    request: Request,
    connection_id: str,
    body: CloudConnectionUpdate,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Update a connection's recurring scan schedule (tenant-scoped).

    Sets ``scan_interval_minutes`` (null disables recurring scans). The encrypted
    secret is untouched and never returned.
    """
    record = _require_connection(request, connection_id)
    from agent_bom.api.managed_trial import enforce_connection_envelope, managed_trial_enabled

    next_interval = record.scan_interval_minutes
    if "scan_interval_minutes" in body.model_fields_set:
        next_interval = _validate_scan_interval(body.scan_interval_minutes)
    next_scope = _validate_inventory_scope(body.inventory_scope) if body.inventory_scope is not None else record.inventory_scope
    next_mode = _validate_scan_mode(body.scan_mode) if body.scan_mode is not None else record.scan_mode
    if record.provider == "databricks":
        from agent_bom.cloud.databricks_connection import validate_scan_options

        try:
            validate_scan_options(record.role_ref, next_scope, next_mode, record.regions)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Databricks supports workspace-scoped full scans only.") from exc
    enforce_connection_envelope(
        provider=record.provider,
        regions=record.regions,
        inventory_scope=next_scope,
        scan_mode=next_mode,
        scan_interval_minutes=next_interval,
    )
    if "scan_interval_minutes" in body.model_fields_set:
        record.scan_interval_minutes = next_interval
    if body.inventory_scope is not None:
        record.inventory_scope = _validate_inventory_scope(body.inventory_scope)
    if body.scan_mode is not None:
        record.scan_mode = _validate_scan_mode(body.scan_mode)
    if body.auto_scan_on_create is not None:
        record.auto_scan_on_create = bool(body.auto_scan_on_create)
    if managed_trial_enabled():
        record.auto_scan_on_create = False
    record.updated_at = _now()
    get_connection_store().put(record)
    log_action(
        "cloud_connection.update",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=record.tenant_id,
        provider=record.provider,
    )
    return record.to_public_dict()


@router.delete("/cloud/connections/{connection_id}", status_code=204)
def delete_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> None:
    """Delete a connection owned by the authenticated tenant."""
    record = _require_connection(request, connection_id)
    get_connection_store().delete(record.tenant_id, record.id)
    log_action(
        "cloud_connection.delete",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=record.tenant_id,
        provider=record.provider,
    )


@router.post("/cloud/connections/{connection_id}/test")
async def test_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Validate a stored connection's brokered read-only credential.

    This is the pre-scan button for hosted POCs and self-hosted onboarding. It is
    tenant-scoped, uses the same RBAC gate as scans, and never runs inventory/CIS
    or writes findings. On success the connection becomes ``active``; on failure
    it becomes ``error`` with sanitized status detail.
    """

    record = _require_connection(request, connection_id)
    _reject_showcase_connection(record)
    from agent_bom.api.managed_trial import enforce_stored_connection_envelope

    enforce_stored_connection_envelope(record)
    tenant_id = record.tenant_id
    actor = _actor(request)

    if (record.provider or "").strip().lower() not in _SCAN_RUNNERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{record.provider}'.")

    try:
        # The broker exchange is synchronous provider network I/O; run it in a
        # worker thread under backpressure so a hung endpoint can never stall
        # the event loop (a burst sheds with a 429 instead).
        async with adaptive_backpressure("cloud_connection_test"):
            with anyio.fail_after(15):
                probe_result = await anyio.to_thread.run_sync(
                    _test_connection_broker,
                    record,
                    abandon_on_cancel=True,
                )
    except BackpressureRejectedError as exc:
        # A shed request never reached the broker — do not flip the connection
        # to error, just ask the caller to retry.
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except Exception as exc:  # noqa: BLE001 - broker/provider failure
        from agent_bom.cloud.capability_probe import (
            CapabilityProbeError,
            classify_probe_failure,
            probe_failure_detail,
        )

        classified = classify_probe_failure(exc)
        if isinstance(exc, (CapabilityProbeError, TimeoutError)) or classified != "unavailable":
            probe_status = classified
            detail = probe_failure_detail(probe_status)
        else:
            probe_status = "unavailable"
            detail = _safe_connection_detail(exc)
        _mark_connection(
            record,
            status=STATUS_ERROR,
            status_detail=detail,
            capability_probe_status=probe_status,
            verified_capabilities=[],
        )
        _logger.error("Cloud connection test failed for connection %s", record.id)
        log_action(
            "cloud_connection.test",
            actor=actor,
            resource=f"cloud-connection/{record.id}",
            tenant_id=tenant_id,
            provider=record.provider,
            outcome="failure",
        )
        # Surface the actionable, sanitized reason (why + how to fix) to the
        # caller, not a "see server logs" dead end.
        raise HTTPException(status_code=502, detail=detail) from exc

    capabilities = list(probe_result.capabilities)
    _mark_connection(
        record,
        status=STATUS_ACTIVE,
        status_detail="",
        capability_probe_status="verified",
        verified_capabilities=capabilities,
    )
    log_action(
        "cloud_connection.test",
        actor=actor,
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
        outcome="success",
    )
    return {
        "schema_version": "cloud.connections.test.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": record.provider,
        "status": "ok",
        "credential_present": record.to_public_dict()["credential_present"],
        "capability_probe_status": "verified",
        "verified_capabilities": capabilities,
        "audit_metadata": _scan_audit_metadata(
            "Connection test brokered a read-only credential only; no inventory, CIS, findings, or resource writes ran."
        ),
        "connection": record.to_public_dict(),
    }


@router.post(
    "/cloud/connections/{connection_id}/scan",
    response_model=CloudConnectionScanAccepted,
    status_code=202,
)
async def scan_connection(
    request: Request,
    connection_id: str,
    _role: Any = _SCAN_DEP,
) -> CloudConnectionScanAccepted:
    """Queue a durable read-only scan for a stored cloud connection.

    Returns immediately with a stable job id. The existing scan worker resolves
    the tenant-scoped connection, brokers short-lived read-only credentials, and
    persists inventory/CIS findings through the normal scan and graph stores.
    Poll ``GET /v1/scan/{job_id}`` for completion. ``Idempotency-Key`` makes an
    HTTP retry return the original accepted job.
    """
    from agent_bom.api import scan_job_dispatch, scan_job_submission
    from agent_bom.api.idempotency_store import IdempotencyConflictError, idempotency_request_fingerprint
    from agent_bom.api.models import JobStatus, ScanRequest
    from agent_bom.api.stores import _get_idempotency_store, _get_store

    record = _require_connection(request, connection_id)
    _reject_showcase_connection(record)
    from agent_bom.api.managed_trial import enforce_stored_connection_envelope

    enforce_stored_connection_envelope(record)
    tenant_id = record.tenant_id
    actor = _actor(request)

    if (record.provider or "").strip().lower() not in _SCAN_RUNNERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{record.provider}'.")

    endpoint = f"/v1/cloud/connections/{record.id}/scan"
    idempotency_key = str(request.headers.get("Idempotency-Key", "") or "").strip()
    request_hash = idempotency_request_fingerprint({"connection_id": record.id})
    idempotency_source = "cloud-connection-scan"
    from agent_bom.api.stores import _jobs_pop
    from agent_bom.api.tenant_quota import (
        consume_managed_trial_scan_credit,
        enforce_active_scan_quota,
        enforce_retained_jobs_quota,
    )

    job: ScanJob | None = None
    # One tenant admission critical section covers idempotency replay, job
    # capacity, durable reservation, and the managed-trial scan credit.  The
    # scan helper is told the guard is already held, avoiding the former nested
    # non-reentrant lock.  Dispatch occurs only after the reservation is fully
    # durable and the lock is released.
    with tenant_quota_guard(tenant_id):
        if idempotency_key:
            try:
                cached = _get_idempotency_store().get(
                    endpoint,
                    tenant_id,
                    idempotency_source,
                    idempotency_key,
                    request_hash=request_hash,
                )
            except IdempotencyConflictError as exc:
                raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
            if cached is not None:
                cached_job_id = str(cached.get("job_id") or "")
                existing = _get_store().get(cached_job_id, tenant_id=tenant_id) if cached_job_id else None
                if existing is not None:
                    if existing.status is JobStatus.FAILED:
                        raise HTTPException(status_code=503, detail="Cloud connection scan could not be queued.")
                    return _accepted_connection_scan(existing, record)

        try:
            enforce_active_scan_quota(tenant_id)
            enforce_retained_jobs_quota(tenant_id)
            job = scan_job_submission.enqueue_scan_job(
                tenant_id=tenant_id,
                triggered_by=actor,
                request_body=ScanRequest(),
                source_id=f"{_QUEUED_CONNECTION_SOURCE_PREFIX}{record.id}",
                quota_guarded=True,
                dispatch=False,
            )
            consume_managed_trial_scan_credit(tenant_id)
            if idempotency_key:
                _get_idempotency_store().put(
                    endpoint,
                    tenant_id,
                    idempotency_source,
                    idempotency_key,
                    {"job_id": job.job_id},
                    request_hash=request_hash,
                )
        except HTTPException:
            if job is not None:
                _get_store().delete(job.job_id, tenant_id=tenant_id)
                _jobs_pop(job.job_id, tenant_id=job.tenant_id)
            raise
        except Exception as exc:  # noqa: BLE001 - durable admission boundary
            if job is not None:
                _get_store().delete(job.job_id, tenant_id=tenant_id)
                _jobs_pop(job.job_id, tenant_id=job.tenant_id)
            _logger.error(
                "Cloud connection scan reservation failed connection=%s: %s",
                record.id,
                sanitize_text(sanitize_error(exc, generic=True)),
            )
            raise HTTPException(status_code=503, detail="Cloud connection scan could not be queued.") from None

    assert job is not None  # narrowed after successful admission
    try:
        scan_job_dispatch.dispatch_scan_job(job)
    except Exception as exc:  # noqa: BLE001 - local/shared dispatch boundary
        from agent_bom.api.stores import _jobs_put

        job.status = JobStatus.FAILED
        job.completed_at = _now()
        job.error = "Scan dispatch failed before execution."
        job.progress.append("Dispatch failed before execution")
        await anyio.to_thread.run_sync(_get_store().put, job)
        _jobs_put(job.job_id, job, compact_terminal=True)
        _logger.error(
            "Cloud connection scan dispatch failed connection=%s job=%s: %s",
            record.id,
            job.job_id,
            sanitize_text(sanitize_error(exc, generic=True)),
        )
        raise HTTPException(status_code=503, detail="Cloud connection scan could not be queued.") from None
    log_action(
        "cloud_connection.scan",
        actor=actor,
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
        outcome="accepted",
        job_id=job.job_id,
    )
    return _accepted_connection_scan(job, record)


_EXPORTS = {
    "_MAX_AUTH_PARAMS": "agent_bom.api.connection_request_validation",
    "_MAX_AUTH_PARAM_KEY_LEN": "agent_bom.api.connection_request_validation",
    "_MAX_AUTH_PARAM_VALUE_LEN": "agent_bom.api.connection_request_validation",
    "_MAX_SCAN_INTERVAL_MINUTES": "agent_bom.api.connection_request_validation",
    "_REGION_RE": "agent_bom.api.connection_request_validation",
    "_MAX_REGIONS": "agent_bom.api.connection_request_validation",
    "_MAX_STATUS_DETAIL": "agent_bom.api.connection_scan_reports",
    "_cis_summary": "agent_bom.api.connection_scan_reports",
    "_annotate_inventory_counts": "agent_bom.api.connection_scan_reports",
    "_persist_connection_report": "agent_bom.api.connection_scan_reports",
    "_mark_connection_report_sources": "agent_bom.api.connection_scan_reports",
    "_run_azure_connection_scan": "agent_bom.api.connection_scan_providers",
    "_run_gcp_connection_scan": "agent_bom.api.connection_scan_providers",
    "_snowflake_estate_summary": "agent_bom.api.connection_scan_providers",
    "_run_snowflake_connection_scan": "agent_bom.api.connection_scan_providers",
    "_run_databricks_connection_scan": "agent_bom.api.connection_scan_providers",
    "_run_aws_connection_scan": "agent_bom.api.connection_scan_aws",
    "_parse_scope_list": "agent_bom.api.connection_scan_database",
    "_run_database_connection_scan": "agent_bom.api.connection_scan_database",
    "_run_connection_scan": "agent_bom.api.connection_scan_worker",
    "is_queued_connection_scan": "agent_bom.api.connection_scan_worker",
    "execute_queued_connection_scan": "agent_bom.api.connection_scan_worker",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
