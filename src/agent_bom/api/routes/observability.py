"""Tenant-scoped observability and evidence ingestion routes; see generated OpenAPI."""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from importlib import import_module
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from starlette.responses import Response

from agent_bom.api.correlation_cohort_ingest import (
    CorrelationCohortIngestError,
    cohort_evidence_created_at,
    commit_correlation_cohort_child,
    prior_or_conflict,
    validate_correlation_cohort_child,
)
from agent_bom.api.demo_refresh import demo_daily_evidence_dependency
from agent_bom.api.experimental_gate import require_experimental
from agent_bom.api.hub_ingest import ingest_runtime_findings
from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyReservationHeartbeat,
    deterministic_batch_id,
    idempotency_owner_token,
    idempotency_request_fingerprint,
    idempotency_reservation_lease_seconds,
)
from agent_bom.api.managed_trace_pull import managed_trace_pull
from agent_bom.api.models import JobStatus, PushPayload, ScanJob, ScanRequest
from agent_bom.api.observability_costs import _render_prometheus_metrics
from agent_bom.api.observability_events import (
    _dep,
    _extract_ocsf_events,
    _finish_ocsf_ingest,
    _logger,
    _normalize_ocsf_event,
    _now,
    _persist_runtime_observations,
    _tenant_id,
)
from agent_bom.api.observability_push_receipts import (
    _cohort_push_response,
    _graph_snapshot_exists,
    _prepare_push_endpoint,
    _pushed_job_has_persisted_graph,
    _pushed_job_receipt,
    _record_push_trend,
    _release_cohort_push_claim,
    _release_push_idempotency_claim,
    _store_pushed_job,
    _wait_for_cohort_child,
    _wait_for_pushed_job,
)
from agent_bom.api.observability_trace_read import (
    _blast_radius_views_for_tenant,
    _build_trace_explorer_payload_sync,
    _ingest_traces_sync,
    _nhi_by_credential_for_tenant,
    _screen_content_enabled,
    _screen_trace_content_events,
    _trace_explorer_payload_for_tenant,
)
from agent_bom.api.pipeline import _persist_graph_snapshot
from agent_bom.api.push_evidence import audit_push_admission
from agent_bom.api.push_evidence import normalize_pushed_report as _normalize_pushed_report
from agent_bom.api.read_models import documented, observability
from agent_bom.api.routes.observability_finops import router as finops_router
from agent_bom.api.runtime_event_store import get_runtime_event_store
from agent_bom.api.stores import _get_graph_store, _get_idempotency_store, _get_store
from agent_bom.api.tenant_quota import enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.api.trace_collection.routes import router as trace_collection_router
from agent_bom.api.trace_connection_broker import public_connections, pull_credentials
from agent_bom.config import API_MAX_OCSF_INGEST_EVENTS
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error, sanitize_text

_MAX_RUNTIME_OFFSET = 1_000_000_000


router = APIRouter(dependencies=[Depends(demo_daily_evidence_dependency)])


router.include_router(
    trace_collection_router,
    dependencies=[cast(Any, require_authenticated_permission("runtime_ingest")), require_experimental("traces")],
)


infra_router = APIRouter()


_RUNTIME_READ: dict[str, Any] = {"tags": ["runtime", "observability"], "dependencies": [require_authenticated_permission("read")]}


_CONNECTOR_READ: dict[str, Any] = {
    "tags": ["observability", "connectors"],
    "dependencies": [require_authenticated_permission("read"), require_experimental("traces")],
}


def _triggered_by(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "push"


@router.post("/traces", tags=["observability"])
async def ingest_traces(request: Request, body: dict, screen_content: bool | None = None) -> dict:
    """Ingest OTLP metadata and flag candidate vulnerable tool calls.

    Opt-in Shield content screening stays in memory; raw content is never persisted.
    """
    tenant_id = _tenant_id(request)
    try:
        return await asyncio.to_thread(_ingest_traces_sync, body, tenant_id, _screen_content_enabled(screen_content))
    except ValueError as exc:
        # A malformed OTLP payload is the caller's error, not ours. The blanket
        # 500 this replaced both mis-signalled 5xx alerting and echoed the raw
        # parser exception text back to the client.
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.error("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@router.post("/traces/attack-paths", tags=["observability"], dependencies=[_dep("read"), require_experimental("traces")])
def correlate_trace_attack_paths(request: Request, body: dict, span_id: str | None = None) -> dict[str, object]:
    """Return name-based finding candidates for traced tool calls.

    These legacy associations are not exact inventory joins or execution proof.
    They relate reported tool/server names to the tenant's scan blast radii.
    Correlation is in-memory; raw span content is never stored. Pass ``span_id``
    to scope the answer to a single span.
    """
    from agent_bom.otel_ingest import parse_otel_traces
    from agent_bom.runtime_correlation import correlate_spans_to_attack_paths

    tenant_id = _tenant_id(request)
    try:
        traces = parse_otel_traces(body)
    except ValueError as exc:
        # 422 matches the sibling ingest route and every Pydantic-modelled body
        # on the write path — one status for one class of bad input.
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    if span_id:
        traces = [t for t in traces if t.span_id == span_id]

    blast_radii = _blast_radius_views_for_tenant(tenant_id)
    nhi_by_credential = _nhi_by_credential_for_tenant(tenant_id)
    attack_paths = correlate_spans_to_attack_paths(traces, blast_radii, nhi_by_credential=nhi_by_credential)
    return {
        "schema_version": "observability.trace_attack_paths.v1",
        "tenant_id": tenant_id,
        "spans": len(traces),
        "count": len(attack_paths),
        "attack_paths": [path.to_dict() for path in attack_paths],
    }


@router.get("/traces/connectors", **documented(observability.TraceConnectorsResponse), **_CONNECTOR_READ)
def list_trace_connectors_route(request: Request) -> dict[str, object]:
    """List native trace-pull connectors (Langfuse, LangSmith)."""
    from agent_bom.trace_connectors import list_trace_connectors

    return {
        "schema_version": "observability.trace_connectors.v1",
        "connectors": list_trace_connectors(),
        "connections": public_connections(_tenant_id(request)),
    }


@router.post(
    "/traces/connectors/{provider}/pull",
    tags=["observability", "connectors"],
    dependencies=[_dep("runtime_ingest"), require_experimental("traces")],
)
def pull_trace_connector(request: Request, provider: str, body: dict) -> dict[str, object]:
    """Import via a managed connection or correlate one-shot provider credentials.
    Screening is opt-in; provider responses may still contain content.
    """
    from agent_bom.otel_ingest import parse_otel_traces
    from agent_bom.runtime_correlation import correlate_spans_to_attack_paths
    from agent_bom.trace_connectors import (
        TraceConnectorError,
        TraceConnectorValidationError,
        fetch_traces,
    )

    tenant_id = _tenant_id(request)
    credentials = pull_credentials(tenant_id, provider, body, actor=_triggered_by(request))
    try:
        limit = max(1, min(int(body.get("limit", 50) or 50), 1000))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'limit' must be an integer") from exc
    raw_screen = body.get("screen_content")
    if raw_screen is not None and not isinstance(raw_screen, bool):
        raise HTTPException(status_code=400, detail="'screen_content' must be a boolean")
    screen_content = _screen_content_enabled(raw_screen)

    if "connection_id" in body:
        return managed_trace_pull(
            provider=provider,
            body=body,
            credentials=credentials,
            tenant_id=tenant_id,
            actor=_triggered_by(request),
            store=get_runtime_event_store(),
            limit=limit,
            screen_content=screen_content,
            screen=lambda payload: _screen_trace_content_events(payload, tenant_id=tenant_id),
            findings=lambda: _blast_radius_views_for_tenant(tenant_id),
            identities=lambda: _nhi_by_credential_for_tenant(tenant_id),
            finding_sink=ingest_runtime_findings,
        )

    try:
        otlp = fetch_traces(provider, credentials, limit=limit, include_content=screen_content)
    except TraceConnectorValidationError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    except TraceConnectorError as exc:
        raise HTTPException(status_code=502, detail=sanitize_error(exc)) from exc

    traces = parse_otel_traces(otlp)
    blast_radii = _blast_radius_views_for_tenant(tenant_id)
    nhi_by_credential = _nhi_by_credential_for_tenant(tenant_id)
    attack_paths = correlate_spans_to_attack_paths(traces, blast_radii, nhi_by_credential=nhi_by_credential)
    content_findings = _screen_trace_content_events(otlp, tenant_id=tenant_id) if screen_content else []
    return {
        "schema_version": "observability.trace_connectors.v1",
        "tenant_id": tenant_id,
        "provider": provider.strip().lower(),
        "pulled_spans": len(traces),
        "content_screened": screen_content,
        "attack_paths": [path.to_dict() for path in attack_paths],
        "content_findings": content_findings,
    }


_RECOGNIZED_PUSH_EXTRA_KEYS = frozenset(
    {
        "blast_radius",
        "scan_id",
        "summary",
        "posture_scorecard",
        "findings",
        "packages",
        "vulnerabilities",
        "agent_projects",
        "report",
        "observed_at",
    }
)


@router.post("/results/push", tags=["push"], status_code=201)
async def receive_push(request: Request, body: PushPayload) -> dict:
    """Receive pushed scan results from a CLI instance.

    Stores as a completed ScanJob with source metadata.
    """
    # ``model_fields_set`` includes ``extra="allow"`` keys, so intersect with the
    # declared fields to see whether the client set a real push field.
    provided_declared = body.model_fields_set & set(type(body).model_fields)
    extra_keys = set(body.model_extra or {})
    if not provided_declared and not (extra_keys & _RECOGNIZED_PUSH_EXTRA_KEYS):
        raise HTTPException(
            status_code=422,
            detail=(
                "results push payload missing recognized fields; expected at least one of source_id, agents, blast_radii, warnings, summary"
            ),
        )
    if body.endpoint_inventory is not None and not body.source_id:
        raise HTTPException(status_code=422, detail="endpoint_inventory requires a stable source_id")
    tenant_id = _tenant_id(request)
    cohort_id = (body.correlation_cohort_id or "").strip()
    cohort_receipt = body.correlation_child_receipt
    if bool(cohort_id) != bool(cohort_receipt):
        raise HTTPException(status_code=422, detail="Correlation cohort id and child receipt must be provided together")
    if cohort_id and cohort_receipt is not None:
        if not body.source_id:
            raise HTTPException(status_code=422, detail="Correlation cohort result requires source_id")
        request_hash = idempotency_request_fingerprint(body)
        cohort_claimed = False
        cohort_owner = idempotency_owner_token()
        cohort_heartbeat: IdempotencyReservationHeartbeat | None = None
        cohort_child_id = cohort_receipt.child_job_id
        try:
            context = validate_correlation_cohort_child(
                tenant_id=tenant_id,
                source_id=body.source_id,
                correlation_cohort_id=cohort_id,
                receipt=cohort_receipt,
                allowed_source_kinds={"ingest.result_push"},
            )
            try:
                _receipt, cohort_claimed = _get_idempotency_store().claim(
                    "/v1/results/push/cohort",
                    tenant_id,
                    body.source_id,
                    cohort_child_id,
                    {"job_id": cohort_child_id, "committed": False},
                    request_hash=request_hash,
                    reservation_lease_seconds=idempotency_reservation_lease_seconds(),
                    owner_token=cohort_owner,
                )
            except IdempotencyConflictError as exc:
                raise CorrelationCohortIngestError("duplicate_result") from exc
            if not cohort_claimed:
                completed = await _wait_for_cohort_child(
                    cohort_child_id,
                    tenant_id=tenant_id,
                    source_id=body.source_id,
                    request_hash=request_hash,
                )
                if completed is None:
                    raise HTTPException(
                        status_code=409,
                        detail="An identical correlation cohort result is still being committed; retry shortly.",
                        headers={"Retry-After": "1"},
                    )
                return _cohort_push_response(*completed)
            cohort_heartbeat = IdempotencyReservationHeartbeat(
                _get_idempotency_store(),
                "/v1/results/push/cohort",
                tenant_id,
                body.source_id,
                cohort_child_id,
                request_hash=request_hash,
                owner_token=cohort_owner,
                lease_seconds=idempotency_reservation_lease_seconds(),
            )
            cohort_heartbeat.__enter__()
            current_child = await asyncio.to_thread(_get_store().get, cohort_child_id, tenant_id)
            if current_child is None:
                raise CorrelationCohortIngestError("invalid_receipt")
            context = type(context)(parent=context.parent, child=current_child)
            replay = prior_or_conflict(context.child, request_hash=request_hash)
            if replay is not None:
                parent = _get_store().get(replay.parent_job_id or "", tenant_id=tenant_id)
                if parent is None:
                    raise CorrelationCohortIngestError("invalid_receipt")
                cohort_heartbeat.ensure_owned()
                cohort_heartbeat.__exit__()
                cohort_heartbeat = None
                replay, parent = await asyncio.to_thread(
                    _get_idempotency_store().commit_claim,
                    "/v1/results/push/cohort",
                    tenant_id,
                    body.source_id,
                    cohort_child_id,
                    {"job_id": cohort_child_id, "committed": True},
                    action=lambda: (replay, parent),
                    request_hash=request_hash,
                    owner_token=cohort_owner,
                )
                return _cohort_push_response(replay, parent)
            report = _normalize_pushed_report(body, fallback_scan_id=context.child.job_id)
            supplied_scan_id = str(report.get("scan_id") or "")
            if supplied_scan_id != context.child.job_id and "scan_id" in (body.model_extra or {}):
                raise CorrelationCohortIngestError("invalid_receipt")
            observed_at = next(
                (
                    str(report.get(key) or "").strip()
                    for key in ("observed_at", "scan_timestamp", "generated_at")
                    if str(report.get(key) or "").strip()
                ),
                "",
            )
            report["observed_at"] = cohort_evidence_created_at(
                [observed_at] if observed_at else [],
                max_age_hours=cohort_receipt.max_age_hours,
            )
            report["scan_id"] = context.child.job_id
            report["pushed"] = True
            audit_push_admission(context.child, report, actor=_triggered_by(request), request_hash=request_hash)
            cohort_heartbeat.ensure_owned()
            cohort_heartbeat.__exit__()
            cohort_heartbeat = None
            child, parent = await asyncio.to_thread(
                _get_idempotency_store().commit_claim,
                "/v1/results/push/cohort",
                tenant_id,
                body.source_id,
                cohort_child_id,
                {"job_id": cohort_child_id, "committed": True},
                action=lambda: commit_correlation_cohort_child(
                    context,
                    result=report,
                    request_hash=request_hash,
                    persist_graph=_persist_graph_snapshot,
                ),
                request_hash=request_hash,
                owner_token=cohort_owner,
            )
            return _cohort_push_response(child, parent)
        except CorrelationCohortIngestError as exc:
            current = await asyncio.to_thread(_get_store().get, cohort_child_id, tenant_id)
            if cohort_claimed and (current is None or current.status is not JobStatus.DONE):
                _release_cohort_push_claim(
                    tenant_id=tenant_id,
                    source_id=body.source_id,
                    child_id=cohort_child_id,
                    request_hash=request_hash,
                    owner_token=cohort_owner,
                )
            if exc.code == "durable_store_required":
                detail = "Correlation cohort ingest requires durable stores"
            elif exc.code == "stale_evidence":
                detail = "Correlation cohort evidence is stale"
            elif exc.code in {"observation_time_required", "invalid_observation_time"}:
                raise HTTPException(status_code=422, detail="Correlation cohort evidence requires a valid observation time") from exc
            elif exc.code == "duplicate_result":
                detail = "Correlation cohort child already has a different result"
            else:
                detail = "Correlation cohort receipt is invalid"
            raise HTTPException(status_code=409, detail=detail) from exc
        except Exception as exc:  # noqa: BLE001
            current = await asyncio.to_thread(_get_store().get, cohort_child_id, tenant_id)
            if cohort_claimed and (current is None or current.status is not JobStatus.DONE):
                _release_cohort_push_claim(
                    tenant_id=tenant_id,
                    source_id=body.source_id,
                    child_id=cohort_child_id,
                    request_hash=request_hash,
                    owner_token=cohort_owner,
                )
            _logger.error("Correlation cohort result commit failed: %s", sanitize_text(sanitize_error(exc, generic=True)))
            raise HTTPException(status_code=503, detail="Correlation cohort result could not be committed") from exc
        finally:
            if cohort_heartbeat is not None:
                cohort_heartbeat.__exit__()

    request_headers = getattr(request, "headers", {})
    header_idempotency_key = str(request_headers.get("Idempotency-Key") or "").strip()
    body_idempotency_key = str(body.idempotency_key or "").strip()
    if header_idempotency_key and body_idempotency_key and header_idempotency_key != body_idempotency_key:
        raise HTTPException(status_code=409, detail="Idempotency key header and payload do not match")
    idempotency_key = header_idempotency_key or body_idempotency_key
    idempotency_source = body.source_id or "push"
    request_hash = idempotency_request_fingerprint(body)
    idempotency_store = _get_idempotency_store()
    claimed = False
    idempotency_owner = idempotency_owner_token()
    idempotency_heartbeat: IdempotencyReservationHeartbeat | None = None
    reserved_job_id = ""
    if idempotency_key:
        reserved_job_id = deterministic_batch_id(f"/v1/results/push:{tenant_id}:{idempotency_source}:{idempotency_key}:{request_hash}")
        try:
            receipt, claimed = idempotency_store.claim(
                "/v1/results/push",
                tenant_id,
                idempotency_source,
                idempotency_key,
                {"job_id": reserved_job_id, "committed": False},
                request_hash=request_hash,
                reservation_lease_seconds=idempotency_reservation_lease_seconds(),
                owner_token=idempotency_owner,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
        if not claimed:
            existing = await _wait_for_pushed_job(
                str(receipt.get("job_id") or ""),
                tenant_id=tenant_id,
                idempotency_source=idempotency_source,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
            )
            if existing is not None:
                return _pushed_job_receipt(existing)
            raise HTTPException(
                status_code=409,
                detail="An identical pushed result is still being committed; retry shortly.",
                headers={"Retry-After": "1"},
            )
        existing = await asyncio.to_thread(
            _get_store().get,
            str(receipt.get("job_id") or reserved_job_id),
            tenant_id,
        )
        if existing is not None and _pushed_job_has_persisted_graph(existing):
            existing = cast(
                ScanJob,
                await asyncio.to_thread(
                    idempotency_store.commit_claim,
                    "/v1/results/push",
                    tenant_id,
                    idempotency_source,
                    idempotency_key,
                    {"job_id": existing.job_id, "committed": True},
                    action=lambda: existing,
                    request_hash=request_hash,
                    owner_token=idempotency_owner,
                ),
            )
            return _pushed_job_receipt(existing)
        idempotency_heartbeat = IdempotencyReservationHeartbeat(
            idempotency_store,
            "/v1/results/push",
            tenant_id,
            idempotency_source,
            idempotency_key,
            request_hash=request_hash,
            owner_token=idempotency_owner,
            lease_seconds=idempotency_reservation_lease_seconds(),
        )
        idempotency_heartbeat.__enter__()
    job = ScanJob(
        job_id=reserved_job_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        source_id=body.source_id or None,
        triggered_by=f"{_triggered_by(request)}:{body.source_id}" if body.source_id else _triggered_by(request),
        created_at=_now(),
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = _now()

    def _persist() -> dict:
        if idempotency_heartbeat is not None:
            idempotency_heartbeat.ensure_owned()
        job_result = _normalize_pushed_report(body, fallback_scan_id=job.job_id)
        job_result["pushed"] = True
        job.result = job_result
        job.progress.append(f"Received via push from source={sanitize_text(body.source_id)}")
        fleet_store, previous_endpoint, endpoint = _prepare_push_endpoint(body, job, job_result, tenant_id)
        job_store = _get_store()
        job_persisted = False
        endpoint_persisted = False
        graph_scan_id = str(job_result.get("scan_id") or job.job_id)
        # A rollback may only remove what this push wrote. Resolve up front
        # whether a snapshot with this id already existed (another push, or an
        # older client that reused a content-derived id): that snapshot is not
        # ours to delete. Unknown (backend cannot answer) is treated as
        # pre-existing so a failure can never destroy someone else's graph.
        graph_snapshot_preexisted = _graph_snapshot_exists(tenant_id, graph_scan_id)
        # This server-generated token is committed with the graph. A stale
        # absence check cannot authorize deleting another writer's generation.
        graph_write_generation = uuid.uuid4().hex
        # Keep quota admission and all three durable projections in one
        # compensating transaction. Graph persistence is last and atomic within
        # its backend; a failure restores the prior endpoint and removes the job,
        # so retained-job quota cannot diverge from visible evidence.
        with tenant_quota_guard(tenant_id, lambda: enforce_retained_jobs_quota(tenant_id)):
            audit_push_admission(job, job_result, actor=_triggered_by(request), request_hash=request_hash)
            try:
                _store_pushed_job(job_store, job)
                job_persisted = True
                if endpoint is not None:
                    fleet_store.put_endpoint(endpoint)
                    endpoint_persisted = True
                _persist_graph_snapshot(job, job_result, write_generation=graph_write_generation)
                # Publish the graph receipt before committing idempotency.
                _store_pushed_job(job_store, job)
                _record_push_trend(job, job_result, body)
            except Exception:
                if graph_snapshot_preexisted:
                    _logger.warning(
                        "Graph rollback skipped for scan=%s tenant=%s: snapshot existed before this push",
                        sanitize_text(graph_scan_id),
                        sanitize_text(tenant_id),
                    )
                else:
                    try:
                        _get_graph_store().delete_snapshot(
                            tenant_id=tenant_id, scan_id=graph_scan_id, expected_generation=graph_write_generation
                        )
                    except Exception as rollback_exc:  # noqa: BLE001
                        _logger.error("Graph rollback failed: %s", sanitize_text(sanitize_error(rollback_exc, generic=True)))
                if endpoint_persisted and body.source_id:
                    try:
                        if previous_endpoint is None:
                            fleet_store.delete_endpoint(body.source_id, tenant_id=tenant_id)
                        else:
                            fleet_store.put_endpoint(previous_endpoint)
                    except Exception as rollback_exc:  # noqa: BLE001
                        _logger.error("Endpoint rollback failed: %s", sanitize_text(sanitize_error(rollback_exc, generic=True)))
                if job_persisted:
                    try:
                        job_store.delete(job.job_id, tenant_id=tenant_id)
                    except Exception as rollback_exc:  # noqa: BLE001
                        _logger.error("Job rollback failed: %s", sanitize_text(sanitize_error(rollback_exc, generic=True)))
                raise
        return job_result

    try:
        if claimed:
            if idempotency_heartbeat is not None:
                idempotency_heartbeat.ensure_owned()
                idempotency_heartbeat.__exit__()
                idempotency_heartbeat = None
            await asyncio.to_thread(
                idempotency_store.commit_claim,
                "/v1/results/push",
                tenant_id,
                idempotency_source,
                idempotency_key,
                {"job_id": job.job_id, "committed": True},
                action=_persist,
                request_hash=request_hash,
                owner_token=idempotency_owner,
            )
        else:
            await asyncio.to_thread(_persist)
    except HTTPException:
        if claimed:
            _release_push_idempotency_claim(
                idempotency_store,
                tenant_id=tenant_id,
                source_id=idempotency_source,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                owner_token=idempotency_owner,
            )
        raise
    except Exception as exc:  # noqa: BLE001
        if claimed:
            _release_push_idempotency_claim(
                idempotency_store,
                tenant_id=tenant_id,
                source_id=idempotency_source,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                owner_token=idempotency_owner,
            )
        _logger.error("Pushed-result commit failed: %s", sanitize_text(sanitize_error(exc, generic=True)))
        raise HTTPException(status_code=503, detail="Pushed result could not be committed") from exc
    finally:
        if idempotency_heartbeat is not None:
            idempotency_heartbeat.__exit__()
    return _pushed_job_receipt(job)


@router.post("/ocsf/ingest", tags=["observability"], status_code=202)
async def ingest_ocsf(request: Request, body: dict | list[dict]) -> dict:
    """Ingest OCSF events and normalize them onto the canonical runtime-event path."""
    from agent_bom.api.audit_log import log_action

    tenant_id = _tenant_id(request)
    try:
        ocsf_events = _extract_ocsf_events(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    if len(ocsf_events) > API_MAX_OCSF_INGEST_EVENTS:
        raise HTTPException(
            status_code=422,
            detail=f"OCSF ingest accepts at most {API_MAX_OCSF_INGEST_EVENTS} events per request",
        )

    normalized_events = [_normalize_ocsf_event(event, tenant_id=tenant_id) for event in ocsf_events]
    class_counts: dict[str, int] = defaultdict(int)
    for event in normalized_events:
        class_counts[str(event.get("ocsf_class_uid", "unknown"))] += 1

    await asyncio.to_thread(_finish_ocsf_ingest, normalized_events, tenant_id=tenant_id)

    source_ids = sorted({str(event.get("source_id", "")).strip() for event in normalized_events if str(event.get("source_id", "")).strip()})
    log_action(
        "ocsf.ingest",
        actor=_triggered_by(request),
        resource="ocsf/ingest",
        tenant_id=tenant_id,
        batch_size=len(normalized_events),
        class_counts=dict(class_counts),
        source_ids=source_ids,
    )
    return {
        "ingested": len(normalized_events),
        "tenant_id": tenant_id,
        "class_counts": dict(class_counts),
        "sources": source_ids,
    }


@router.post("/runtime/events", tags=["runtime", "observability"], status_code=202, dependencies=[_dep("runtime_ingest")])
def ingest_runtime_events(request: Request, body: dict | list[dict]) -> dict[str, object]:
    """Persist metadata-only runtime observations for tenant-scoped querying."""
    tenant_id = _tenant_id(request)
    if isinstance(body, list):
        events = body
    elif isinstance(body, dict) and isinstance(body.get("events"), list):
        events = body["events"]
    else:
        events = [body]
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise HTTPException(status_code=400, detail="Runtime event ingest expects an event object or events array")
    persisted = _persist_runtime_observations(cast(list[dict[str, Any]], events), tenant_id=tenant_id, source="runtime")
    return {
        "schema_version": "runtime.observability.v1",
        "persisted": persisted,
        "tenant_id": tenant_id,
        "redaction_status": "metadata_only",
        "raw_payload_stored": False,
    }


@router.get("/runtime/sessions", **documented(observability.RuntimeSessionsResponse), **_RUNTIME_READ)
def list_runtime_sessions(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=_MAX_RUNTIME_OFFSET)] = 0,
) -> dict[str, object]:
    """List tenant-scoped runtime sessions derived from persisted observations."""
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 500))
    bounded_offset = max(0, offset)
    sessions = get_runtime_event_store().list_sessions(tenant_id, limit=bounded_limit, offset=bounded_offset)
    return {
        "schema_version": "runtime.observability.v1",
        "tenant_id": tenant_id,
        "count": len(sessions),
        "limit": bounded_limit,
        "offset": bounded_offset,
        "sessions": [session.to_dict() for session in sessions],
    }


@router.get("/runtime/observations", **documented(observability.RuntimeObservationsResponse), **_RUNTIME_READ)
def list_runtime_observations(
    request: Request,
    session_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=_MAX_RUNTIME_OFFSET)] = 0,
) -> dict[str, object]:
    """List metadata-only runtime observations for the active tenant."""
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 500))
    bounded_offset = max(0, offset)
    observations = get_runtime_event_store().list_observations(
        tenant_id,
        session_id=session_id,
        limit=bounded_limit,
        offset=bounded_offset,
    )
    return {
        "schema_version": "runtime.observability.v1",
        "tenant_id": tenant_id,
        "count": len(observations),
        "limit": bounded_limit,
        "offset": bounded_offset,
        "observations": [observation.to_dict() for observation in observations],
    }


@router.get("/runtime/observation-revisions", **documented(observability.RuntimeObservationsResponse), **_RUNTIME_READ)
def list_runtime_observation_revisions(
    request: Request,
    observation_id: Annotated[str, Query(min_length=1, max_length=512)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=_MAX_RUNTIME_OFFSET)] = 0,
) -> dict[str, object]:
    """Read tenant-scoped metadata history; it is not independent provider proof."""
    tenant_id = _tenant_id(request)
    rows = get_runtime_event_store().list_observation_revisions(tenant_id, observation_id, limit=limit, offset=offset)
    return {
        "schema_version": "runtime.observability.v1",
        "tenant_id": tenant_id,
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "observations": [row.to_dict() for row in rows],
    }


@router.get("/runtime/trace-explorer", **documented(observability.RuntimeTraceExplorerResponse), **_RUNTIME_READ)
async def trace_explorer(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    scan_id: Annotated[str | None, Query(max_length=512)] = None,
    offset: Annotated[int, Query(ge=0, le=_MAX_RUNTIME_OFFSET)] = 0,
    session_id: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
    source: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
    agent_name: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
    connection_id: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
) -> dict[str, object]:
    """Read bounded runtime traces off-loop; name matches remain candidates."""
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 200))
    return await asyncio.to_thread(
        _build_trace_explorer_payload_sync,
        tenant_id,
        limit=bounded_limit,
        scan_id=scan_id,
        offset=offset,
        session_id=session_id,
        source=source,
        agent_name=agent_name,
        connection_id=connection_id,
    )


@router.get("/runtime/approval-queue", **documented(observability.RuntimeApprovalQueueResponse), **_RUNTIME_READ)
async def runtime_approval_queue(
    request: Request,
    status: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> dict[str, object]:
    """List blocked runtime spans awaiting or after human approval (#3617)."""
    from agent_bom.api.hitl_approval_queue import build_hitl_queue_items
    from agent_bom.api.hitl_approval_store import get_hitl_approval_store

    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 200))
    trace_payload = await _trace_explorer_payload_for_tenant(tenant_id, limit=bounded_limit)
    status_filter = status.strip().lower() if status else None
    if status_filter not in {None, "", "pending", "approved", "denied"}:
        raise HTTPException(status_code=400, detail="status must be pending, approved, or denied")
    items = build_hitl_queue_items(
        tenant_id=tenant_id,
        trace_payload=trace_payload,
        store=get_hitl_approval_store(),
        status_filter=status_filter or None,
    )
    pending = sum(1 for item in items if item.get("status") == "pending")
    return {
        "schema_version": "runtime.approval_queue.v1",
        "tenant_id": tenant_id,
        "count": len(items),
        "pending_count": pending,
        "items": items[:bounded_limit],
    }


class _HitlDecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str
    note: str = ""


@router.post(
    "/runtime/approval-queue/{item_id}/decision",
    tags=["runtime", "observability"],
    dependencies=[_dep("policy.manage")],
)
async def runtime_approval_decision(request: Request, item_id: str, body: _HitlDecisionBody) -> dict[str, object]:
    """Approve or deny a blocked runtime span; emits a signed audit event."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.hitl_approval_queue import apply_hitl_decision, build_hitl_queue_items
    from agent_bom.api.hitl_approval_store import get_hitl_approval_store

    tenant_id = _tenant_id(request)
    actor = _triggered_by(request)
    store = get_hitl_approval_store()
    trace_payload = await _trace_explorer_payload_for_tenant(tenant_id, limit=200)
    queue_items = build_hitl_queue_items(
        tenant_id=tenant_id,
        trace_payload=trace_payload,
        store=store,
    )
    queue_item = next((item for item in queue_items if item.get("item_id") == item_id), None)
    if queue_item is None:
        raise HTTPException(status_code=404, detail="Approval queue item not found")
    try:
        record = apply_hitl_decision(
            tenant_id=tenant_id,
            item_id=item_id,
            decision=body.decision,
            actor=actor,
            note=body.note,
            queue_item=queue_item,
            store=store,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    log_action(
        "runtime.hitl_decision",
        actor=actor,
        resource=f"runtime/approval-queue/{item_id}",
        tenant_id=tenant_id,
        decision=record.status.value,
        span_id=record.span_id,
        agent=record.agent,
        tool=record.tool,
        linked_finding_ids=record.linked_finding_ids,
        compliance_controls=record.compliance_controls,
        note=record.note,
    )
    return {
        "schema_version": "runtime.approval_queue.v1",
        "item": record.to_dict(),
    }


@router.get("/runtime/sessions/{session_id}/observations", **documented(observability.RuntimeSessionObservationsResponse), **_RUNTIME_READ)
def list_runtime_session_observations(
    request: Request,
    session_id: str,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=_MAX_RUNTIME_OFFSET)] = 0,
) -> dict[str, object]:
    """List observations for one runtime session in the active tenant."""
    tenant_id = _tenant_id(request)
    session = get_runtime_event_store().get_session(tenant_id, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Runtime session not found")
    observations = get_runtime_event_store().list_observations(
        tenant_id,
        session_id=session_id,
        limit=max(1, min(limit, 500)),
        offset=max(0, offset),
    )
    return {
        "schema_version": "runtime.observability.v1",
        "tenant_id": tenant_id,
        "session": session.to_dict(),
        "count": len(observations),
        "observations": [observation.to_dict() for observation in observations],
    }


@router.post("/ui/errors", tags=["observability"], dependencies=[_dep("read")])
def ingest_ui_error(request: Request, body: dict) -> dict:
    """Ingest a sanitized client-side dashboard error report."""
    from agent_bom.api.audit_log import log_action

    def _sanitize_log_value(value: object, max_len: int) -> str:
        text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
        text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
        return text[:max_len]

    tenant_id = _tenant_id(request)
    message = _sanitize_log_value(body.get("message", ""), 500)
    digest = _sanitize_log_value(body.get("digest", ""), 128)
    path = _sanitize_log_value(body.get("path", ""), 256)
    component = _sanitize_log_value(body.get("component", "dashboard"), 128) or "dashboard"
    log_action(
        "ui.client_error",
        actor=_triggered_by(request),
        resource="ui/error",
        tenant_id=tenant_id,
        message=message,
        digest=digest,
        path=path,
        component=component,
    )
    log_component = _sanitize_log_value(component, 128) or "dashboard"
    log_digest = _sanitize_log_value(digest, 128)
    log_path = _sanitize_log_value(path, 256)
    _logger.warning(
        "ui client error tenant=%s component=%s digest=%s path=%s",
        tenant_id,
        log_component,
        log_digest,
        log_path,
    )
    return {"ok": True}


@infra_router.get("/metrics", tags=["observability"], dependencies=[_dep("read")])
async def prometheus_metrics(request: Request) -> Response:
    return await _render_prometheus_metrics(request)


router.include_router(finops_router)

_EXPORTS = {
    "_bounded": "agent_bom.api.observability_events",
    "_build_llm_costs_report_sync": "agent_bom.api.observability_costs",
    "_slug": "agent_bom.api.observability_events",
    "_ocsf_timestamp": "agent_bom.api.observability_events",
    "_ocsf_finding_detector": "agent_bom.api.observability_events",
    "_event_session_id": "agent_bom.api.observability_events",
    "_runtime_observation_from_event": "agent_bom.api.observability_events",
    "_COST_CENTER_KEYS": "agent_bom.api.observability_costs",
    "_ALLOCATION_TAG_PREFIX": "agent_bom.api.observability_costs",
    "_MAX_ALLOCATION_TAGS": "agent_bom.api.observability_costs",
    "_attr_str": "agent_bom.api.observability_costs",
    "_allocation_for_spans": "agent_bom.api.observability_costs",
    "_read_allocation_attrs": "agent_bom.api.observability_costs",
    "_persist_llm_costs": "agent_bom.api.observability_costs",
    "get_llm_cost_budget": "agent_bom.api.routes.observability_finops",
    "get_anomalies": "agent_bom.api.routes.observability_finops",
    "get_llm_cost_forecast": "agent_bom.api.routes.observability_finops",
    "set_llm_cost_budget": "agent_bom.api.routes.observability_finops",
    "get_llm_costs": "agent_bom.api.routes.observability_finops",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
