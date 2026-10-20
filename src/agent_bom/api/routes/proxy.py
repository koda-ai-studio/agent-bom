"""Proxy status, runtime production index, alerts, shield, and WebSocket streaming API routes.

Endpoints:
    GET       /v1/proxy/status       proxy metrics summary
    GET       /v1/proxy/alerts       recent proxy alerts (filterable)
    POST      /v1/shield/start       start deep defense protection engine
    GET       /v1/shield/status      shield threat assessment
    POST      /v1/shield/unblock     deactivate kill-switch
    WebSocket /ws/proxy/metrics      live metrics stream (1 Hz)
    WebSocket /ws/proxy/alerts       live alert stream"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from functools import partial
from importlib import import_module
from threading import Lock
from typing import Any, cast

import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket

from agent_bom.api import websocket_auth
from agent_bom.api.demo_refresh import demo_daily_evidence_dependency
from agent_bom.api.gateway_activity_store import (
    GatewayActivityConflictError,
    GatewayActivityRecord,
    gateway_activity_record_from_event,
    get_gateway_activity_store,
)
from agent_bom.api.idempotency_store import IdempotencyConflictError, idempotency_request_fingerprint
from agent_bom.api.models import ProxyAuditIngestRequest
from agent_bom.api.proxy_log_read import _MAX_EVIDENCE_LOG_LINES, _get_configured_log_path, _read_alerts_from_log, _read_metrics_from_log
from agent_bom.api.proxy_provenance import GatewaySubmissionProvenance, canonicalize_proxy_submission
from agent_bom.api.proxy_runtime_projection import _alert_visible_to_tenant, _build_runtime_production_index, _summarize_proxy_alerts
from agent_bom.api.read_models import ProxyAlertsResponse, ProxyStatusResponse, documented
from agent_bom.api.read_models import runtime_estate_b as rt
from agent_bom.api.shield_registry import _MAX_SHIELD_SESSIONS, _get_engine, _shield_engines, _shield_engines_lock, _shield_key
from agent_bom.api.stores import _get_idempotency_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.runtime.gateway_events import GATEWAY_CANONICAL_EVENT_TYPES, GATEWAY_DENIED_EVENT_TYPES
from agent_bom.security import sanitize_error, sanitize_sensitive_payload

router = APIRouter(dependencies=[Depends(demo_daily_evidence_dependency)])


_logger = logging.getLogger("agent_bom.api.routes.proxy")


ws_router = APIRouter()


_proxy_alerts: deque[dict] = deque(maxlen=1000)


_proxy_alerts_total: int = 0


_proxy_metrics: dict | None = None


_proxy_metrics_by_tenant: dict[str, dict] = {}


AUDIT_DEDUPE_WINDOW_SECONDS = 24 * 60 * 60


AUDIT_DEDUPE_MAX_ENTRIES = 50_000


_audit_dedupe: "OrderedDict[tuple[str, str], float]" = OrderedDict()


_audit_dedupe_lock = Lock()


def _purge_expired_dedupe(now: float) -> None:
    cutoff = now - AUDIT_DEDUPE_WINDOW_SECONDS
    while _audit_dedupe:
        key, ts = next(iter(_audit_dedupe.items()))
        if ts >= cutoff:
            break
        _audit_dedupe.popitem(last=False)
    while len(_audit_dedupe) > AUDIT_DEDUPE_MAX_ENTRIES:
        _audit_dedupe.popitem(last=False)


def _claim_audit_event(tenant_id: str, event_id: str) -> bool:
    """Reserve a (tenant, event_id) pair. Returns True if new, False if replay."""
    if not event_id:
        return True
    now = time.time()
    key = (tenant_id or "default", event_id)
    with _audit_dedupe_lock:
        _purge_expired_dedupe(now)
        if key in _audit_dedupe:
            return False
        _audit_dedupe[key] = now
        return True


def _reset_audit_dedupe_for_tests() -> None:
    """Test helper to clear the dedupe table between cases."""
    with _audit_dedupe_lock:
        _audit_dedupe.clear()


def _reset_proxy_runtime_for_tests() -> None:
    """Test helper to clear the process-global proxy alert/metric ring buffers.

    The alert deque and metrics maps are module-global (the ring buffer is
    process-wide), so seeded demo data or per-test alerts otherwise leak across
    tests. Callers pair this with the firewall decision store reset.
    """
    global _proxy_alerts_total, _proxy_metrics
    _proxy_alerts.clear()
    _proxy_alerts_total = 0
    _proxy_metrics = None
    _proxy_metrics_by_tenant.clear()


def _reset_ws_handshake_rate_limit_for_tests() -> None:
    websocket_auth._reset_ws_handshake_rate_limit_for_tests()


def push_proxy_alert(alert: dict, *, submission_provenance: GatewaySubmissionProvenance | None = None) -> None:
    """Called by the proxy to record a runtime alert (in-process path)."""
    global _proxy_alerts_total
    sanitized = sanitize_sensitive_payload(alert)
    safe = redact_for_persistence(sanitized, EvidenceTier.SAFE_TO_STORE)
    projected = safe if isinstance(safe, dict) else {}
    projected.pop("submission_provenance", None)
    projected["producer_assurance"] = "unknown"
    if isinstance(submission_provenance, GatewaySubmissionProvenance):
        submission_provenance = GatewaySubmissionProvenance.model_validate(submission_provenance)
        projected["submission_provenance"] = submission_provenance.model_dump()
        projected["producer_assurance"] = submission_provenance.producer_assurance
    _proxy_alerts.append(projected)
    _proxy_alerts_total += 1


def push_proxy_metrics(metrics: dict, *, submission_provenance: GatewaySubmissionProvenance | None = None) -> None:
    """Record latest metrics with a server-authoritative receipt timestamp."""
    global _proxy_metrics
    sanitized = sanitize_sensitive_payload(metrics)
    _proxy_metrics = sanitized if isinstance(sanitized, dict) else {}
    _proxy_metrics.pop("submission_provenance", None)
    _proxy_metrics["producer_assurance"] = "unknown"
    if isinstance(submission_provenance, GatewaySubmissionProvenance):
        submission_provenance = GatewaySubmissionProvenance.model_validate(submission_provenance)
        _proxy_metrics["submission_provenance"] = submission_provenance.model_dump()
        _proxy_metrics["producer_assurance"] = submission_provenance.producer_assurance
    # ``metrics`` crosses a process/HTTP trust boundary. Preserve any client
    # event timestamp for event provenance, but never let it establish runtime
    # transport freshness. A caller-controlled future ``received_at`` would
    # otherwise keep the Gateway Feed labeled live indefinitely.
    _proxy_metrics["received_at"] = datetime.now(timezone.utc).isoformat()
    tenant_id = str(_proxy_metrics.get("tenant_id") or "default")
    _proxy_metrics_by_tenant[tenant_id] = dict(_proxy_metrics)


def _request_tenant_id(request: Request) -> str:
    """Return the authenticated tenant for HTTP proxy endpoints."""
    return require_request_tenant_id(request)


_CANONICAL_GATEWAY_EVENT_TYPES = GATEWAY_CANONICAL_EVENT_TYPES


def _gateway_activity_record_from_alert(
    alert: dict[str, Any],
    *,
    tenant_id: str,
    source_id: str,
    session_id: str,
    received_at: datetime,
    request_trace_id: str,
    submission_provenance: GatewaySubmissionProvenance | None = None,
) -> GatewayActivityRecord | None:
    """Project one gateway-shaped alert onto the strict metadata-only ledger.

    Historical audit envelopes contain extra proxy fields and may omit the
    event timestamp emitted by the standalone gateway. Only canonical gateway
    events with caller-observed time enter the durable ledger; inventing an
    ingestion timestamp would change the event digest on every retry. Older
    timestamp-free records remain an explicitly degraded ring-buffer event.

    Raises:
        ValueError: when a canonical gateway event omits ``event_id`` or
            ``event_timestamp``. The id is the ledger's dedupe key and the
            timestamp is the caller-observed time the ledger orders by; without
            either the event can only reach the process-local ring — and
            answering ``2xx`` would acknowledge a gateway decision that was
            never committed. A canonical event is durably stored or rejected;
            it is never silently downgraded.
    """

    event_type = str(alert.get("event_type") or "")
    if event_type not in _CANONICAL_GATEWAY_EVENT_TYPES:
        # Not a canonical gateway event at all — a legacy proxy envelope, which
        # the ring-only path still serves.
        return None
    event_id = str(alert.get("event_id") or "").strip()
    if not event_id:
        raise ValueError("canonical gateway event requires a non-empty event_id")
    event_timestamp = alert.get("event_timestamp") or alert.get("timestamp")
    if isinstance(event_timestamp, int | float) and not isinstance(event_timestamp, bool):
        try:
            event_timestamp = datetime.fromtimestamp(float(event_timestamp), tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("canonical gateway event requires a representable event_timestamp") from exc
    if not isinstance(event_timestamp, str) or not event_timestamp.strip():
        raise ValueError("canonical gateway event requires event_timestamp")
    expected_decision = "deny" if event_type in GATEWAY_DENIED_EVENT_TYPES else "allow"
    agent_id = str(alert.get("agent_id") or alert.get("agent_name") or alert.get("source_agent") or source_id or "unknown")
    canonical: dict[str, Any] = {
        "schema_version": "gateway.runtime.event.v1",
        "event_id": event_id,
        "decision_id": str(alert.get("decision_id") or event_id),
        "event_type": event_type,
        "event_timestamp": event_timestamp,
        "agent_id": agent_id,
        "upstream": str(alert.get("upstream") or alert.get("target") or "unknown"),
        "tool": str(alert.get("tool") or alert.get("tool_name") or "unknown"),
        "decision": str(alert.get("decision") or expected_decision),
        "policy_source": str(alert.get("policy_source") or "legacy_proxy"),
        "trace_id": str(alert.get("trace_id") or event_id),
    }
    for field in (
        "identity_id",
        "profile_id",
        "blueprint_id",
        "reason_code",
        "data_action",
        "policy_id",
        "evidence_id",
    ):
        value = alert.get(field)
        if isinstance(value, str):
            canonical[field] = value
    for field in ("profile_revision", "blueprint_revision"):
        value = alert.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            canonical[field] = value
    policy_ids = alert.get("policy_ids")
    if isinstance(policy_ids, list | tuple):
        canonical["policy_ids"] = list(policy_ids)
    if isinstance(alert.get("development_mode"), bool):
        canonical["development_mode"] = alert["development_mode"]
    return gateway_activity_record_from_event(
        canonical,
        submission_provenance=submission_provenance,
        receipt_trace_id=request_trace_id,
        tenant_id=tenant_id,
        source_id=source_id,
        session_id=session_id,
        received_at=received_at,
    )


def _append_gateway_activity_resilient(
    records: list[GatewayActivityRecord],
) -> tuple[set[str], set[str], set[str]]:
    """Append a batch, isolating conflicting IDs without losing valid peers."""

    store = get_gateway_activity_store()
    try:
        result = store.append_batch(records)
        return set(result.inserted_event_ids), set(result.duplicate_event_ids), set()
    except GatewayActivityConflictError:
        inserted: set[str] = set()
        duplicates: set[str] = set()
        conflicts: set[str] = set()
        for record in records:
            try:
                result = store.append_batch([record])
            except GatewayActivityConflictError:
                conflicts.add(record.event_id)
                continue
            inserted.update(result.inserted_event_ids)
            duplicates.update(result.duplicate_event_ids)
        return inserted, duplicates, conflicts


@router.post("/proxy/audit", tags=["proxy"])
async def ingest_proxy_audit(request: Request, body: ProxyAuditIngestRequest) -> dict:
    """Ingest alerts and summary from an external proxy process."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.stores import _get_analytics_store

    actor = getattr(request.state, "api_key_name", "") or "proxy-client"
    tenant_id = require_request_tenant_id(request)
    request_id = getattr(request.state, "request_id", "") or ""
    trace_id = getattr(request.state, "trace_id", "") or ""
    source_id = body.source_id or "unknown"
    session_id = body.session_id or "default"
    analytics_events: list[dict] = []
    try:
        _, submission_context = canonicalize_proxy_submission({}, source_id=source_id, session_id=session_id, request_state=request.state)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid proxy submission context") from exc
    source_id = submission_context.submission_source_id
    session_id = submission_context.submission_session_id
    request_hash = idempotency_request_fingerprint({"body": body.model_dump(), "submission_context": submission_context.model_dump()})
    if body.idempotency_key:
        try:
            cached = _get_idempotency_store().get(
                "/v1/proxy/audit",
                tenant_id,
                source_id,
                body.idempotency_key,
                request_hash=request_hash,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
        if cached is not None:
            cached["idempotent_replay"] = True
            return cast("dict[Any, Any]", cached)

    from agent_bom.api.stores import _get_firewall_decision_store

    firewall_store = _get_firewall_decision_store()
    received_at = datetime.now(timezone.utc)
    prepared_alerts: list[dict[str, Any]] = []
    submission_metadata: dict[int, GatewaySubmissionProvenance] = {}
    activity_records: list[GatewayActivityRecord] = []
    summary = None
    summary_provenance = None
    if body.summary:
        try:
            summary, summary_provenance = canonicalize_proxy_submission(
                body.summary, source_id=source_id, session_id=session_id, request_state=request.state
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid proxy submission context") from exc
    for alert in body.alerts:
        try:
            enriched, provenance = canonicalize_proxy_submission(
                alert, source_id=source_id, session_id=session_id, request_state=request.state
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid proxy submission context") from exc
        submission_metadata[id(enriched)] = provenance
        enriched.setdefault("request_id", request_id)
        enriched["receipt_trace_id"] = trace_id
        # Receipt time is transport metadata owned by this API process. Never
        # accept a caller-supplied future value into degraded feed ordering.
        enriched["received_at"] = received_at.isoformat()
        enriched.setdefault("event_type", enriched.get("action") or enriched.get("type", "runtime_alert"))
        enriched["tenant_id"] = tenant_id
        prepared_alerts.append(enriched)
        try:
            record = _gateway_activity_record_from_alert(
                enriched,
                tenant_id=tenant_id,
                source_id=source_id,
                session_id=session_id,
                received_at=received_at,
                request_trace_id=trace_id,
                submission_provenance=provenance,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid canonical gateway activity event") from exc
        # Request correlation is receipt metadata, not producer event identity.
        # Keep it on the ring/audit view after constructing the stable event.
        enriched.setdefault("trace_id", trace_id)
        if record is not None:
            activity_records.append(record)
    activity_candidate_ids = {record.event_id for record in activity_records}

    durable_inserted_ids: set[str] = set()
    durable_duplicate_ids: set[str] = set()
    durable_conflict_ids: set[str] = set()
    if activity_records:
        try:
            inserted_ids, duplicate_ids, conflict_ids = await anyio.to_thread.run_sync(
                _append_gateway_activity_resilient,
                activity_records,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid canonical gateway activity batch") from exc
        except Exception as exc:  # noqa: BLE001 - storage failure is a safe 503
            raise HTTPException(status_code=503, detail="Gateway activity storage unavailable") from exc
        durable_inserted_ids.update(inserted_ids)
        durable_duplicate_ids.update(duplicate_ids)
        durable_conflict_ids.update(conflict_ids)

    duplicate_event_ids: list[str] = []
    accepted_alerts: list[dict] = []
    consumed_durable_ids: set[str] = set()
    for enriched in prepared_alerts:
        # dedupe by event_id so a buggy or hostile proxy
        # cannot replay credential_leak alerts and inflate per-detector
        # tallies. Empty event_id falls through to keep legacy callers working.
        event_id = str(enriched.get("event_id") or "")
        canonical_gateway = event_id in activity_candidate_ids
        if canonical_gateway:
            if event_id in durable_conflict_ids:
                continue
            if event_id in durable_duplicate_ids or event_id in consumed_durable_ids:
                duplicate_event_ids.append(event_id)
                continue
            if event_id not in durable_inserted_ids:
                duplicate_event_ids.append(event_id)
                continue
            consumed_durable_ids.add(event_id)
            enriched["gateway_activity_durable"] = True
        elif event_id and not _claim_audit_event(tenant_id, event_id):
            duplicate_event_ids.append(event_id)
            continue
        elif str(enriched.get("event_type") or "") in _CANONICAL_GATEWAY_EVENT_TYPES:
            enriched["gateway_activity_durable"] = False
        accepted_alerts.append(enriched)
        push_proxy_alert(enriched, submission_provenance=submission_metadata[id(enriched)])
        # Tally inter-agent firewall decisions for the runtime-tab dashboard
        # (#982 PR 4). Non-firewall alerts are silently ignored by record().
        try:
            firewall_store.record(tenant_id=tenant_id, event=enriched)
        except Exception:  # noqa: BLE001 — store is best-effort, never block ingest
            pass
        analytics_events.append(
            redact_for_persistence(
                {
                    "event_id": enriched.get("event_id", ""),
                    "event_timestamp": enriched.get("event_timestamp") or enriched.get("timestamp") or enriched.get("ts"),
                    "tenant_id": tenant_id,
                    "event_type": enriched.get("event_type", enriched.get("type", "runtime_alert")),
                    "detector": enriched.get("detector", ""),
                    "severity": enriched.get("severity", "INFO"),
                    "tool_name": enriched.get("tool_name", enriched.get("tool", "")),
                    "message": enriched.get("message", ""),
                    "agent_name": enriched.get("agent_name") or enriched.get("agent_id") or enriched.get("source_agent", ""),
                    "session_id": enriched.get("session_id", ""),
                    "trace_id": enriched.get("trace_id", ""),
                    "request_id": enriched.get("request_id", ""),
                    "source_id": enriched.get("source_id", ""),
                },
                EvidenceTier.SAFE_TO_STORE,
            )
        )

        analytics_events[-1]["submission_provenance"] = submission_metadata[id(enriched)]
        analytics_events[-1]["producer_assurance"] = "caller_asserted"

    if summary is not None:
        summary.setdefault("request_id", request_id)
        summary.setdefault("trace_id", trace_id)
        # Server-authoritative tenant tag — never honor a client-supplied
        # tenant_id, which would route this summary into another tenant's
        # metrics bucket on shared deployments.
        summary["tenant_id"] = tenant_id
        push_proxy_metrics(summary, submission_provenance=summary_provenance)

    if analytics_events:
        try:
            await anyio.to_thread.run_sync(partial(_get_analytics_store().record_events, analytics_events, tenant_id=tenant_id))
        except Exception:
            pass

    # count both the alerts that crossed the wire and the
    # runtime_alerts surfaced via summary so credential_leak detections always
    # register, regardless of which envelope key the caller used.
    summary_runtime_alerts = 0
    if isinstance(body.summary, dict):
        candidate = body.summary.get("runtime_alerts")
        if isinstance(candidate, int):
            summary_runtime_alerts = max(0, candidate)
        elif isinstance(candidate, list):
            summary_runtime_alerts = len(candidate)
    accepted_count = len(accepted_alerts)
    effective_alert_count = max(accepted_count, summary_runtime_alerts)

    log_action(
        "proxy.audit_ingested",
        actor=actor,
        resource=f"proxy/{source_id}",
        tenant_id=tenant_id,
        session_id=session_id,
        request_id=request_id,
        trace_id=trace_id,
        alert_count=effective_alert_count,
        duplicate_alert_count=len(duplicate_event_ids),
        has_summary=body.summary is not None,
    )
    response = {
        "ingested": True,
        "source_id": source_id,
        "session_id": session_id,
        "alert_count": effective_alert_count,
        "accepted_alert_count": accepted_count,
        "duplicate_alert_count": len(duplicate_event_ids),
        "duplicate_event_ids": duplicate_event_ids,
        "durable_accepted_count": len(durable_inserted_ids),
        "durable_duplicate_count": len(durable_duplicate_ids),
        "durable_conflict_count": len(durable_conflict_ids),
        "durable_conflict_event_ids": sorted(durable_conflict_ids),
        "has_summary": body.summary is not None,
    }
    if body.idempotency_key:
        _get_idempotency_store().put(
            "/v1/proxy/audit",
            tenant_id,
            source_id,
            body.idempotency_key,
            response,
            request_hash=request_hash,
        )
    return response


def _load_proxy_alerts(tenant_id: str = "default", *, limit: int | None = None) -> list[dict]:
    """Return in-memory alerts, or fall back to the configured audit log.

    ``limit`` bounds the JSONL fallback read and defaults to
    :data:`_MAX_EVIDENCE_LOG_LINES`. The feed passes the smaller
    :data:`_MAX_FEED_LOG_LINES`; evidence callers take the default.
    """
    log_path = _get_configured_log_path()
    if log_path and not _proxy_alerts:
        alerts = _read_alerts_from_log(log_path, limit=_MAX_EVIDENCE_LOG_LINES if limit is None else limit)
    else:
        alerts = list(_proxy_alerts)
    return [alert for alert in alerts if _alert_visible_to_tenant(alert, tenant_id)]


def _runtime_metrics_for_tenant(tenant_id: str) -> dict | None:
    metrics: dict | None = None
    if _proxy_metrics is not None:
        tenant_metrics = _proxy_metrics_by_tenant.get(tenant_id)
        if tenant_metrics is not None:
            metrics = dict(tenant_metrics)
        elif _alert_visible_to_tenant(_proxy_metrics, tenant_id):
            metrics = dict(_proxy_metrics)
    else:
        log_path = _get_configured_log_path()
        if log_path:
            metrics = _read_metrics_from_log(log_path, tenant_id)
            if metrics is not None:
                metrics = dict(metrics)
    return metrics


@router.get("/proxy/status", **documented(ProxyStatusResponse), tags=["proxy"])
def proxy_status(request: Request) -> dict:
    """Get runtime proxy metrics.

    Returns the latest proxy metrics summary.  Reads from the in-process
    buffer (populated by ``push_proxy_metrics``) or from the audit log
    configured via the ``AGENT_BOM_LOG`` environment variable.
    """
    tenant_id = _request_tenant_id(request)
    metrics: dict | None = None
    if _proxy_metrics is not None:
        tenant_metrics = _proxy_metrics_by_tenant.get(tenant_id)
        if tenant_metrics is not None:
            metrics = dict(tenant_metrics)
        elif _alert_visible_to_tenant(_proxy_metrics, tenant_id):
            metrics = dict(_proxy_metrics)
    else:
        log_path = _get_configured_log_path()
        if log_path:
            metrics = _read_metrics_from_log(log_path, tenant_id)
            if metrics is not None:
                metrics = dict(metrics)

    from agent_bom.api.routes.gateway_feed import _feed_health_from_metrics

    if metrics is not None:
        metrics["health"] = _feed_health_from_metrics(metrics)
        metrics["producer_assurance"] = metrics["health"]["producer_assurance"]
        alert_summary = _summarize_proxy_alerts(_load_proxy_alerts(tenant_id))
        metrics["alert_summary"] = {key: value for key, value in alert_summary.items() if key != "recent_alerts"}
        metrics["recent_alerts"] = alert_summary["recent_alerts"]
        return metrics

    return {
        "status": "no_proxy_session",
        "health": _feed_health_from_metrics(None),
        "producer_assurance": "unknown",
        "message": "No proxy metrics available. Start a proxy session or set AGENT_BOM_LOG.",
    }


@router.get("/runtime/production-index", **documented(rt.RuntimeProductionIndexResponse), tags=["runtime", "proxy"])
def runtime_production_index(request: Request) -> dict:
    """Return tenant-scoped runtime security observability for proxy/gateway traffic.

    The production index is metadata-only by construction: it summarizes
    tool-call volume, policy decisions, alerts, source/session activity, and
    retention posture without returning raw prompts, raw arguments, raw
    responses, or credential values.
    """
    tenant_id = _request_tenant_id(request)
    metrics = _runtime_metrics_for_tenant(tenant_id)
    alerts = _load_proxy_alerts(tenant_id)
    return _build_runtime_production_index(tenant_id, metrics, alerts)


@router.get("/proxy/alerts", **documented(ProxyAlertsResponse), tags=["proxy"])
def proxy_alerts(
    request: Request,
    severity: str | None = None,
    detector: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000, description="Max alerts to return (1-1000)"),
) -> dict:
    """Get recent runtime proxy alerts.

    Returns alerts from the in-process buffer or the audit log configured
    via the ``AGENT_BOM_LOG`` environment variable.

    Query params:
        severity: Filter by severity (critical, high, medium, low, info).
        detector: Filter by detector name.
        limit: Maximum number of alerts to return (default 100).
    """
    tenant_id = _request_tenant_id(request)
    alerts = _load_proxy_alerts(tenant_id)

    # The summary describes the tenant's whole alert population, so it agrees
    # with /v1/proxy/metrics and does not shrink to whatever page was asked for.
    # Summarising the filtered/paged slice made the histogram read 100% of the
    # requested severity and understated the estate by the page size.
    summary = _summarize_proxy_alerts(alerts)
    matched_total = len(alerts)

    # Apply filters
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
    if detector:
        alerts = [a for a in alerts if a.get("detector", "").lower() == detector.lower()]
    if severity or detector:
        matched_total = len(alerts)

    # Newest first, apply limit
    alerts = alerts[-limit:][::-1]

    return {
        "alerts": alerts,
        "count": len(alerts),
        "matched_total": matched_total,
        "summary": summary,
        "filters": {
            "severity": severity,
            "detector": detector,
            "limit": limit,
        },
    }


@ws_router.websocket("/ws/proxy/metrics")
async def ws_proxy_metrics(websocket: WebSocket) -> None:
    """WebSocket endpoint — push proxy metrics every second.

    Connect to ``ws://localhost:8422/ws/proxy/metrics`` to receive a live
    stream of proxy metrics as JSON objects.  Useful for building real-time
    dashboards without polling.

    Authentication: when API auth is configured, send
    ``{"type":"auth","token":"..."}`` as the first message or use an
    Authorization bearer token. API keys in query strings are rejected to keep
    credentials out of URL logs.

    Message format (sent every second):
    ::

        {
          "ts": 1234567890.123,
          "tool_calls": {"read_file": 12, "exec": 3},
          "blocked": {"rate_limit": 1, "policy": 2},
          "alerts_last_60s": 4,
          "latency_p95_ms": 45.2
        }

    Connection is closed cleanly on disconnect.
    """
    import asyncio
    import time as _time

    from agent_bom.api.routes.gateway_feed import _feed_health_from_metrics

    try:
        from fastapi.websockets import WebSocketDisconnect
    except ImportError:
        from starlette.websockets import WebSocketDisconnect

    auth_context = await websocket_auth._ws_accept_and_check_auth(websocket)
    if auth_context is None:
        return
    tenant_id = auth_context.tenant_id

    try:
        while await websocket_auth._ws_stream_authorized(websocket, auth_context):
            now = _time.time()
            # Build snapshot from in-process metrics buffer
            metrics_snapshot = _runtime_metrics_for_tenant(tenant_id) or {}

            # Delivery time is not a heartbeat from the submitting runtime.
            receipt_health = _feed_health_from_metrics(metrics_snapshot)

            # Count alerts in last 60 seconds
            cutoff = now - 60
            recent_alerts = [a for a in _proxy_alerts if a.get("ts", 0) > cutoff and _alert_visible_to_tenant(a, tenant_id)]

            if not await websocket_auth.send_stream_json(
                websocket,
                auth_context,
                {
                    "ts": now,
                    "health": receipt_health,
                    "producer_assurance": receipt_health["producer_assurance"],
                    "tool_calls": metrics_snapshot.get("calls_by_tool", {}),
                    "blocked": metrics_snapshot.get("blocked_by_reason", {}),
                    "alerts_last_60s": len(recent_alerts),
                    "latency_p95_ms": metrics_snapshot.get("latency", {}).get("p95_ms"),
                    "total_tool_calls": metrics_snapshot.get("total_tool_calls", 0),
                    "total_blocked": metrics_snapshot.get("total_blocked", 0),
                    "uptime_seconds": metrics_snapshot.get("uptime_seconds"),
                },
            ):
                return
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        # Client disconnected or error — close quietly
        pass


@ws_router.websocket("/ws/proxy/alerts")
async def ws_proxy_alerts(websocket: WebSocket) -> None:
    """WebSocket endpoint — push new proxy alerts as they arrive.

    Streams new alerts in real time.  Each message is a single alert object.
    Useful for live security dashboards that need immediate notification.

    Authentication: when API auth is configured, send
    ``{"type":"auth","token":"..."}`` as the first message or use an
    Authorization bearer token. API keys in query strings are rejected to keep
    credentials out of URL logs.

    Uses a monotonic total counter (not deque length) to detect new alerts
    correctly even when old entries are evicted from the 1000-entry ring buffer.
    """
    import asyncio

    try:
        from fastapi.websockets import WebSocketDisconnect
    except ImportError:
        from starlette.websockets import WebSocketDisconnect

    auth_context = await websocket_auth._ws_accept_and_check_auth(websocket)
    if auth_context is None:
        return
    tenant_id = auth_context.tenant_id

    seen = _proxy_alerts_total  # monotonic — tracks absolute count, not deque position
    try:
        while await websocket_auth._ws_stream_authorized(websocket, auth_context):
            current = _proxy_alerts_total
            if current > seen:
                new_count = min(current - seen, len(_proxy_alerts))
                for alert in list(_proxy_alerts)[-new_count:]:
                    if not _alert_visible_to_tenant(alert, tenant_id):
                        continue
                    if not await websocket_auth.send_stream_json(websocket, auth_context, alert):
                        return
                seen = current
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass


@router.post("/shield/start", tags=["shield"])
def shield_start(request: Request, session_id: str = "default", correlation_window: float = 30.0) -> dict:
    """Start the deep defense protection engine for a session.

    Each session_id gets an isolated engine — zero trust, no cross-session
    threat contamination.

    Query params:
        session_id: Session identifier (default "default").
        correlation_window: Alert correlation window in seconds (default 30).
    """
    from agent_bom.alerts.dispatcher import AlertDispatcher
    from agent_bom.runtime.protection import ProtectionEngine

    tenant_id = _request_tenant_id(request)
    key = _shield_key(tenant_id, session_id)
    # Runs in the threadpool: the check / evict / insert sequence must be
    # atomic so concurrent starts cannot double-create or over-evict engines.
    with _shield_engines_lock:
        existing = _get_engine(tenant_id, session_id)
        if existing is not None and existing.active:
            return {
                "status": "already_active",
                "tenant_id": tenant_id,
                "session_id": session_id,
                **existing.status(),
            }

        # Evict oldest idle session if at capacity
        if len(_shield_engines) >= _MAX_SHIELD_SESSIONS:
            idle = next(
                (candidate_key for candidate_key, eng in _shield_engines.items() if not eng.active),
                next(iter(_shield_engines)),  # fallback: evict oldest
            )
            old = _shield_engines.pop(idle)
            if old.active:
                old.stop()

        dispatcher = AlertDispatcher()
        from agent_bom.api.routes.proxy import push_proxy_alert

        class _RingBufferChannel:
            async def send(self, alert: dict) -> bool:
                push_proxy_alert(alert)
                return True

        dispatcher.add_channel(_RingBufferChannel())

        engine = ProtectionEngine(
            dispatcher=dispatcher,
            shield=True,
            correlation_window=correlation_window,
        )
        engine.start()
        _shield_engines[key] = engine
        return {"status": "started", "tenant_id": tenant_id, "session_id": session_id, **engine.status()}


@router.get("/shield/status", **documented(rt.ShieldStatusResponse), tags=["shield"])
def shield_status(request: Request, session_id: str = "default") -> dict:
    """Get current shield threat assessment for a session."""
    tenant_id = _request_tenant_id(request)
    engine = _get_engine(tenant_id, session_id)
    if engine is None or not engine.active:
        return {
            "active": False,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "message": "Shield not started. POST /v1/shield/start to activate.",
        }

    assessment = engine.assess_threat()
    return {
        "tenant_id": tenant_id,
        "session_id": session_id,
        **engine.status(),
        "assessment": {
            "threat_level": assessment.threat_level.value,
            "composite_score": assessment.composite_score,
            "detectors_triggered": assessment.detectors_triggered,
            "alert_count_in_window": assessment.alert_count_in_window,
            "blocked": assessment.blocked,
        },
    }


@router.post("/shield/unblock", tags=["shield"])
def shield_unblock(request: Request, session_id: str = "default") -> dict:
    """Deactivate kill-switch for a session and reset to ELEVATED."""
    tenant_id = _request_tenant_id(request)
    engine = _get_engine(tenant_id, session_id)
    if engine is None or not engine.active:
        return {"status": "not_active", "tenant_id": tenant_id, "session_id": session_id}

    if not engine.is_blocked:
        return {"status": "not_blocked", "tenant_id": tenant_id, "session_id": session_id}

    engine.unblock()
    return {"status": "unblocked", "tenant_id": tenant_id, "session_id": session_id, **engine.status()}


@router.post("/shield/break-glass", tags=["shield"])
def break_glass(request: Request, session_id: str = "default", reason: str = "") -> dict:
    """Emergency kill-switch override — admin only, audit logged.

    Immediately unblocks all sessions and logs the override for compliance.
    Requires ``admin`` role (set via ``request.state.api_key_role``).
    """
    role = getattr(request.state, "api_key_role", "viewer")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Break-glass requires admin role")

    tenant_id = _request_tenant_id(request)
    engine = _get_engine(tenant_id, session_id)
    if engine is None or not engine.active:
        # A break-glass ATTEMPT is a privileged action and must always be
        # audited — including when there is no active Shield session to
        # override. Record the attempt + outcome before short-circuiting.
        _audit_break_glass(request, role, session_id, reason, was_blocked=False, outcome="not_active")
        return {"status": "not_active", "tenant_id": tenant_id, "session_id": session_id}

    was_blocked = engine.is_blocked
    if was_blocked:
        engine.unblock()

    # Audit log the break-glass event
    _audit_break_glass(request, role, session_id, reason, was_blocked=was_blocked, outcome="break_glass_activated")

    return {
        "status": "break_glass_activated",
        "tenant_id": tenant_id,
        "session_id": session_id,
        "was_blocked": was_blocked,
        "reason": reason,
        **engine.status(),
    }


def _audit_break_glass(
    request: Request,
    role: str,
    session_id: str,
    reason: str,
    *,
    was_blocked: bool,
    outcome: str,
) -> None:
    """Emit an audit event for a break-glass attempt (success or not).

    Audit-log failures must never block an emergency override, so emission is
    best-effort and swallows exceptions.
    """
    try:
        from agent_bom.api.audit_log import log_action

        tenant_id = require_request_tenant_id(request)
        log_action(
            "break_glass",
            actor=getattr(request.state, "actor", "") or getattr(request.state, "api_key_name", "") or role,
            resource=f"shield/{session_id}",
            tenant_id=tenant_id,
            reason=reason,
            was_blocked=was_blocked,
            outcome=outcome,
        )
    except Exception:  # noqa: BLE001
        pass  # audit log failure must not block emergency override


_EXPORTS = {
    "_MAX_FEED_LOG_LINES": "agent_bom.api.proxy_log_read",
    "_LOG_TAIL_BLOCK_BYTES": "agent_bom.api.proxy_log_read",
    "_read_newest_log_lines": "agent_bom.api.proxy_log_read",
    "_safe_int": "agent_bom.api.proxy_runtime_projection",
    "_safe_float": "agent_bom.api.proxy_runtime_projection",
    "_numeric_mapping": "agent_bom.api.proxy_runtime_projection",
    "_top_items": "agent_bom.api.proxy_runtime_projection",
    "_timestamp_value": "agent_bom.api.proxy_runtime_projection",
    "_latest_timestamp": "agent_bom.api.proxy_runtime_projection",
    "_runtime_retention_posture": "agent_bom.api.proxy_runtime_projection",
    "_classify_authorization_event": "agent_bom.api.proxy_runtime_projection",
    "_authorization_trace": "agent_bom.api.proxy_runtime_projection",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
