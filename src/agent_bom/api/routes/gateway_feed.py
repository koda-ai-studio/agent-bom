"""Gateway Live Feed — unified fleet event stream.

A single normalized, cursor-backed stream that projects the durable gateway
activity ledger with per-agent attribution. Legacy proxy alerts and recent LLM
cost observations remain an explicitly partial initial-page compatibility
projection; cursor resume is ledger-only and server ordered.

    * tool-call authorization decisions  (allowed / blocked)  — durable gateway
      activity ledger
    * data-filter / DLP redaction events  (PII / credential masking applied to
      tool responses)                                         — proxy alert ring
      buffer (credential_leak / pii detectors)
    * recent LLM calls                                          — observability
      cost store (priced OTel GenAI spans)

This module is read-only over those existing stores. It does NOT re-implement
enforcement, DLP, or audit. Postgres/SQLite ledger data is primary;
the in-process ring/JSONL path is labeled degraded and never satisfies a cursor
resume when the ledger is unavailable.

Endpoints:
    GET /v1/gateway/feed       normalized, time-ordered fused event list
    GET /v1/gateway/feed/stream canonical ledger SSE with cursor handoff
    GET /v1/gateway/feed/kpis  KPI header rollup (calls / blocked / shadow-AI /
                               data filters)

All reads are RBAC-gated (``read`` permission), tenant-scoped, and
redaction-safe: only metadata (timestamps, agent identifiers, tool/target
names, action class, short non-secret detail strings) is returned. No raw
arguments, raw responses, or credential values cross this surface — the source
records are projected through the ledger's strict metadata allowlist; degraded
records are sanitized by ``push_proxy_alert`` / ``redact_for_persistence``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from functools import partial
from typing import Any, cast

import anyio.to_thread
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from agent_bom.api.demo_refresh import demo_daily_evidence_dependency
from agent_bom.api.gateway_activity_store import (
    GatewayActivityCursorError,
    GatewayActivityCursorExpiredError,
    GatewayActivityPage,
    GatewayActivityWindowSummary,
    InMemoryGatewayActivityStore,
    get_gateway_activity_store,
)
from agent_bom.api.gateway_feed_health import _parse_iso_timestamp, build_gateway_feed_health
from agent_bom.api.gateway_feed_models import (  # noqa: F401 - re-exported for callers and tests
    GatewayActivityStreamPage,
    GatewayFeedCompletenessModel,
    GatewayFeedEventModel,
    GatewayFeedHealthModel,
    GatewayFeedKpiCompletenessModel,
    GatewayFeedKpisModel,
    GatewayFeedLedgerUnavailableError,
    GatewayFeedResponseModel,
    GatewayFeedWindowModel,
    ProducerAssuranceCountsModel,
)
from agent_bom.api.gateway_feed_normalize import (  # noqa: F401 - re-exported for callers and tests
    _EVENT_TYPES,
    _SHADOW_BLOCK_MARKERS,
    ACTION_DATA_FILTER_APPLIED,
    ACTION_LLM_CALL,
    ACTION_TOOL_CALL_AUTHORIZED,
    ACTION_TOOL_CALL_BLOCKED,
    _alert_agent,
    _alert_policy_ids,
    _alert_revision,
    _alert_target,
    _alert_timestamp,
    _block_detail,
    _bounded_alert_identifier,
    _classify_alert_action,
    _data_filter_detail,
    _feed_order_key,
    _is_shadow_block,
    _normalize_alert_event,
    _normalize_llm_event,
    _now_iso,
    _sort_key,
)
from agent_bom.api.proxy_provenance import (
    producer_assurance_counts,
    producer_assurance_rollup,
    projected_producer_assurance,
)
from agent_bom.api.sse_authorization import AuthorizedEventSourceResponse as EventSourceResponse
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[Depends(demo_daily_evidence_dependency)])

_FEED_SCHEMA_VERSION = "gateway.feed.v1"
_STREAM_MAX_SECONDS = 30.0
_STREAM_POLL_SECONDS = 1.0
_stream_slots = threading.BoundedSemaphore(64)


class GatewayActivityStreamResponse(EventSourceResponse):
    """Bound active streams per worker and publish the SSE response schema."""

    media_type = "text/event-stream"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not _stream_slots.acquire(blocking=False):
            await JSONResponse(
                {"detail": "Gateway activity stream capacity unavailable"},
                status_code=503,
                headers={"Retry-After": "5", "Cache-Control": "no-store"},
            )(scope, receive, send)
            return
        try:
            await super().__call__(scope, receive, send)
        finally:
            _stream_slots.release()


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def build_gateway_feed(
    *,
    tenant_id: str,
    alerts: list[dict[str, Any]],
    llm_records: list[Any],
    limit: int,
) -> dict[str, Any]:
    """Fuse and time-order proxy alerts + LLM cost records into one feed.

    Pure function (no I/O) so the normalization, ordering, tenant scoping, and
    redaction-safety can be unit-tested directly. ``alerts`` are expected to be
    pre-scoped to ``tenant_id`` by the caller (the proxy ring buffer enforces
    tenant visibility on read); LLM records come from the tenant-scoped cost
    store.
    """
    events: list[dict[str, Any]] = []
    for alert in alerts:
        event = _normalize_alert_event(alert, tenant_id)
        if event is not None:
            events.append(event)
    for record in llm_records:
        events.append(_normalize_llm_event(record, tenant_id))

    events.sort(key=_feed_order_key, reverse=True)
    bounded = events[:limit]
    counts = {value: sum(e["producer_assurance"] == value for e in bounded) for value in ("unknown", "caller_asserted")}
    return {
        "producer_assurance": producer_assurance_rollup(counts),
        "producer_assurance_counts": counts,
        "producer_assurance_count_basis": "classified_events",
        "schema_version": _FEED_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "generated_at": _now_iso(),
        "count": len(bounded),
        "events": bounded,
    }


def build_gateway_feed_kpis(
    *,
    tenant_id: str,
    alerts: list[dict[str, Any]],
    llm_records: list[Any],
    uptime_seconds: float | None,
) -> dict[str, Any]:
    """Roll up the KPI header counters from the fused sources.

    Counters:
        * ``calls_today``          — authorized + blocked tool-call events + LLM
                                     calls (all gateway-mediated activity).
        * ``blocked_today``        — blocked tool-call events.
        * ``shadow_ai_blocked``    — subset of blocked events whose reason marks
                                     a shadow / undeclared agent or shadow MCP
                                     server (see ``_is_shadow_block``). Labeled
                                     accurately rather than overclaimed.
        * ``data_filters_applied`` — DLP / redaction events.
        * ``uptime_seconds``       — only emitted when the proxy reports it; never
                                     fabricated.

    The route applies a UTC-midnight-to-request-time window and reports whether
    retention or supplemental source limits make the result partial.
    """
    authorized = 0
    blocked = 0
    shadow_blocked = 0
    data_filters = 0
    for alert in alerts:
        action_type = _classify_alert_action(alert)
        if action_type == ACTION_TOOL_CALL_AUTHORIZED:
            authorized += 1
        elif action_type == ACTION_TOOL_CALL_BLOCKED:
            blocked += 1
            if _is_shadow_block(alert):
                shadow_blocked += 1
        elif action_type == ACTION_DATA_FILTER_APPLIED:
            data_filters += 1

    llm_calls = len(llm_records)
    calls_today = authorized + blocked + llm_calls

    counts = producer_assurance_counts([alert for alert in alerts if _classify_alert_action(alert) is not None])
    counts["unknown"] += llm_calls
    kpis: dict[str, Any] = {
        "producer_assurance": producer_assurance_rollup(counts),
        "producer_assurance_counts": counts,
        "producer_assurance_count_basis": "classified_events",
        "schema_version": _FEED_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "generated_at": _now_iso(),
        "calls_today": calls_today,
        "blocked_today": blocked,
        "shadow_ai_blocked": shadow_blocked,
        "data_filters_applied": data_filters,
        "tool_calls_authorized": authorized,
        "llm_calls": llm_calls,
    }
    if isinstance(uptime_seconds, int | float) and uptime_seconds > 0:
        kpis["uptime_seconds"] = float(uptime_seconds)
    return kpis


def _load_tenant_alerts(tenant_id: str) -> list[dict[str, Any]]:
    """Read tenant-scoped proxy alerts from the existing ring buffer / log.

    Delegates to ``proxy._load_proxy_alerts`` which already enforces per-tenant
    visibility and reads the configured audit log when the in-process buffer is
    empty. This module never mutates that buffer.

    Synchronous by design — route callers offload the complete evidence read.
    """
    from agent_bom.api.routes.proxy import _MAX_FEED_LOG_LINES, _load_proxy_alerts

    return _load_proxy_alerts(tenant_id, limit=_MAX_FEED_LOG_LINES)


def _load_gateway_activity_page(
    tenant_id: str,
    *,
    cursor: str | None,
    limit: int,
) -> tuple[GatewayActivityPage, bool]:
    """Read a forward cursor page, using the newest bounded slice initially."""

    store = get_gateway_activity_store()
    if cursor:
        return store.list_activity(tenant_id, cursor=cursor, limit=limit), False

    bounds = store.list_activity(tenant_id, limit=1)
    retained = max(0, bounds.latest_ordinal - bounds.retention_floor_ordinal + 1)
    if retained <= limit:
        return store.list_activity(tenant_id, limit=limit), False

    after = bounds.latest_ordinal - limit
    page = store.list_activity(
        tenant_id,
        cursor=store.encode_cursor(tenant_id, after),
        limit=limit,
    )
    return page, True


async def _gather_durable_feed_inputs_async(
    tenant_id: str,
    *,
    cursor: str | None,
    limit: int,
) -> tuple[GatewayActivityPage, bool, list[dict[str, Any]], list[Any], bool, bool]:
    """Read the ledger and compatibility sources without blocking the loop."""

    def _load_llm() -> tuple[list[Any], bool]:
        try:
            return _load_tenant_llm_records(tenant_id, limit=limit), True
        except Exception:  # noqa: BLE001 - optional evidence is reported partial
            return [], False

    def _gather() -> tuple[GatewayActivityPage, bool, list[dict[str, Any]], list[Any], bool, bool]:
        try:
            page, older_omitted = _load_gateway_activity_page(tenant_id, cursor=cursor, limit=limit)
        except (GatewayActivityCursorError, GatewayActivityCursorExpiredError):
            raise
        except Exception as exc:  # noqa: BLE001 - caller receives sanitized state only
            if cursor:
                raise GatewayFeedLedgerUnavailableError from exc
            page = GatewayActivityPage(
                tenant_id=tenant_id,
                events=[],
                cursor=None,
                next_cursor=None,
                has_more=False,
                retention_floor_ordinal=1,
                latest_ordinal=0,
                max_events_per_tenant=0,
                dedupe_window_events=0,
            )
            older_omitted = False
            llm_records, observability_available = _load_llm()
            return (
                page,
                older_omitted,
                _load_tenant_alerts(tenant_id),
                llm_records,
                False,
                observability_available,
            )
        if cursor:
            return page, older_omitted, [], [], True, True
        # Legacy proxy-shaped events and cost spans have no ledger ordinal.
        # Keep them only on the initial compatibility projection and never on
        # cursor resumes, where replay-free server ordering is the contract.
        alerts = _load_tenant_alerts(tenant_id)
        ledger_ids = {str(event.get("event_id") or "") for event in page.events}
        compatibility_alerts = [
            alert
            for alert in alerts
            if str(alert.get("event_id") or "") not in ledger_ids
            and (
                str(alert.get("event_type") or "") not in _EVENT_TYPES
                or not str(alert.get("event_id") or "")
                or alert.get("gateway_activity_durable") is False
            )
        ]
        llm_records, observability_available = _load_llm()
        return page, older_omitted, compatibility_alerts, llm_records, True, observability_available

    return await anyio.to_thread.run_sync(_gather)


def _feed_completeness(
    page: GatewayActivityPage,
    *,
    older_omitted: bool,
    supplemental_event_count: int,
    ledger_available: bool,
    observability_available: bool,
) -> dict[str, Any]:
    partial_reasons: list[str] = []
    if not ledger_available:
        partial_reasons.append("ledger_unavailable")
    if page.retention_floor_ordinal > 1:
        partial_reasons.append("retention_floor_advanced")
    if older_omitted:
        partial_reasons.append("bounded_initial_backfill")
    if page.has_more:
        partial_reasons.append("page_limit")
    if supplemental_event_count:
        partial_reasons.append("supplemental_unordered_sources")
    if not observability_available:
        partial_reasons.append("observability_unavailable")
    return {
        "status": "partial" if partial_reasons else "complete",
        "reasons": partial_reasons,
        "server_ordered": ledger_available and supplemental_event_count == 0,
        "retention_floor_ordinal": page.retention_floor_ordinal,
        "latest_ordinal": page.latest_ordinal,
        "max_events_per_tenant": page.max_events_per_tenant,
        "dedupe_window_events": page.dedupe_window_events,
    }


def _load_tenant_uptime(tenant_id: str) -> float | None:
    """Best-effort proxy uptime for the tenant, or None when unreported."""
    from agent_bom.api.routes.proxy import _runtime_metrics_for_tenant

    metrics = _runtime_metrics_for_tenant(tenant_id)
    if not isinstance(metrics, dict):
        return None
    raw = metrics.get("uptime_seconds")
    if isinstance(raw, int | float) and raw > 0:
        return float(raw)
    return None


def _load_tenant_transport_metrics(tenant_id: str) -> dict[str, Any] | None:
    """Return the tenant's latest transport metrics/heartbeat, when reported."""
    from agent_bom.api.routes.proxy import _runtime_metrics_for_tenant

    metrics = _runtime_metrics_for_tenant(tenant_id)
    return metrics if isinstance(metrics, dict) else None


def _feed_health_from_metrics(metrics: dict[str, Any] | None) -> dict[str, Any]:
    if not metrics:
        return build_gateway_feed_health(transport_enabled=False, heartbeat_at=None)
    source_id = str(metrics.get("source_id") or "")
    session_id = str(metrics.get("session_id") or "")
    sample = source_id.startswith("demo-estate") or session_id.startswith("demo-estate")
    # ``received_at`` is stamped by the server at ingestion. Client event
    # timestamps remain useful provenance, but are not transport heartbeats.
    heartbeat = metrics.get("received_at")
    health = build_gateway_feed_health(
        transport_enabled=True,
        heartbeat_at=str(heartbeat) if heartbeat else None,
        sample=sample,
    )
    health["producer_assurance"] = projected_producer_assurance(metrics)
    return health


def _load_tenant_llm_records(tenant_id: str, *, limit: int) -> list[Any]:
    """Read recent priced LLM cost records for the tenant (read-only)."""
    from agent_bom.api.cost_store import get_cost_store

    return list(get_cost_store().list_records(tenant_id, limit=limit))


def _timestamp_in_window(value: object, *, start: datetime, end: datetime) -> bool:
    parsed = _parse_iso_timestamp(str(value) if value else None)
    return parsed is not None and start <= parsed <= end


async def _gather_kpi_inputs_async(
    tenant_id: str,
    *,
    start: datetime,
    end: datetime,
) -> tuple[list[dict[str, Any]], list[Any], GatewayActivityWindowSummary, int, bool, bool, bool]:
    """Load UTC-window KPI evidence and completeness facts off-loop."""

    def _gather() -> tuple[list[dict[str, Any]], list[Any], GatewayActivityWindowSummary, int, bool, bool, bool]:
        try:
            summary = get_gateway_activity_store().summarize_window(
                tenant_id,
                start=start.isoformat(),
                end=end.isoformat(),
            )
            ledger_available = True
        except Exception:  # noqa: BLE001 - degraded status is returned without exception text
            ledger_available = False
            summary = GatewayActivityWindowSummary(
                tenant_id=tenant_id,
                start=start.isoformat(),
                end=end.isoformat(),
                tool_calls_authorized=0,
                blocked=0,
                shadow_blocked=0,
                data_filters=0,
                retention_floor_ordinal=1,
                latest_ordinal=0,
            )
        compatibility_alerts = [
            alert
            for alert in _load_tenant_alerts(tenant_id)
            if (
                not ledger_available
                or str(alert.get("event_type") or "") not in _EVENT_TYPES
                or not str(alert.get("event_id") or "")
                or alert.get("gateway_activity_durable") is False
            )
            and _timestamp_in_window(_alert_timestamp(alert), start=start, end=end)
        ]
        try:
            raw_llm = _load_tenant_llm_records(tenant_id, limit=10_001)
            observability_available = True
        except Exception:  # noqa: BLE001 - optional evidence is reported partial
            raw_llm = []
            observability_available = False
        llm_truncated = len(raw_llm) > 10_000
        llm_records = [
            record for record in raw_llm[:10_000] if _timestamp_in_window(getattr(record, "observed_at", None), start=start, end=end)
        ]
        return (
            compatibility_alerts,
            llm_records,
            summary,
            len(compatibility_alerts),
            llm_truncated,
            ledger_available,
            observability_available,
        )

    return await anyio.to_thread.run_sync(_gather)


def _read_stream_page(tenant_id: str, cursor: str | None, limit: int) -> GatewayActivityStreamPage:
    """Read one bounded, atomic page; never fall back to local compatibility data."""
    store = get_gateway_activity_store()
    if isinstance(store, InMemoryGatewayActivityStore):
        raise GatewayFeedLedgerUnavailableError("Gateway activity streaming requires durable storage")
    page = store.list_activity(tenant_id, cursor=cursor, limit=limit)
    # Even an initially empty ledger needs an explicit checkpoint. Derive it
    # from this read's snapshot, never a second read that could skip an append.
    next_cursor = page.next_cursor or store.encode_cursor(tenant_id, page.latest_ordinal)
    payload = GatewayActivityStreamPage.model_validate(
        {
            "tenant_id": tenant_id,
            "events": page.events,
            "next_cursor": next_cursor,
            "has_more": page.has_more,
            "retention_floor_ordinal": page.retention_floor_ordinal,
            "latest_ordinal": page.latest_ordinal,
            "max_events_per_tenant": page.max_events_per_tenant,
            "dedupe_window_events": page.dedupe_window_events,
        }
    )
    if any(event.tenant_id != tenant_id or event.raw_payload_stored for event in payload.events):
        raise GatewayFeedLedgerUnavailableError("Invalid gateway activity metadata")
    return payload


async def _stream_activity(
    tenant_id: str, first_page: GatewayActivityStreamPage, limit: int, deadline: float
) -> AsyncIterator[dict[str, Any]]:
    """Follow one cursor through backfill and tailing, including across replicas.

    Each data frame is an atomic batch: clients commit its id only after
    processing the entire frame. Backpressure never buffers an unbounded queue;
    retention overtaking a slow reader terminates with an explicit gap.
    """
    page = first_page
    first = True
    while time.monotonic() < deadline:
        if first or page.events:
            yield {
                "event": "activity" if page.events else "checkpoint",
                "id": page.next_cursor,
                "retry": 1000,
                "data": page.model_dump_json(),
            }
            first = False
        # Drain history immediately; only idle/tailing reads wait. Every page
        # read is off-loop and releases its DB connection before any SSE send.
        if not page.has_more:
            await anyio.sleep(min(_STREAM_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        if time.monotonic() >= deadline:
            break
        try:
            page = await anyio.to_thread.run_sync(_read_stream_page, tenant_id, page.next_cursor, limit)
        except GatewayActivityCursorExpiredError as exc:
            yield {"event": "gap", "data": '{"reason":"cursor_expired","retention_floor_ordinal":' + str(exc.retention_floor_ordinal) + "}"}
            return
        except GatewayActivityCursorError:
            # A restored/replaced ledger must not silently rewind the client.
            yield {"event": "gap", "data": '{"reason":"cursor_invalid"}'}
            return
        except Exception:  # noqa: BLE001 - stream has started; only a safe terminal status can be sent
            yield {"event": "unavailable", "data": '{"reason":"ledger_unavailable"}'}
            return
    # Reconnect through the auth middleware; do not renew authorization from
    # the stale request.state. Revocation is rechecked at each new connection.
    yield {"event": "reconnect", "data": '{"reason":"reauthenticate"}'}


@router.get(
    "/gateway/feed/stream",
    tags=["gateway"],
    dependencies=[_dep("read")],
    response_class=GatewayActivityStreamResponse,
    responses={
        200: {
            "model": GatewayActivityStreamPage,
            # FastAPI otherwise adds type=string beside this object's $ref.
            # Describe the JSON data envelope within each SSE activity frame.
            "content": {"text/event-stream": {"schema": {"type": "object"}}},
            "description": "SSE activity/checkpoint data frames; id is the resume cursor. Terminal events: gap, unavailable, reconnect.",
        },
        400: {"description": "Invalid or cross-tenant cursor"},
        401: {"description": "Authentication required, including on loopback"},
        410: {"description": "Cursor precedes retained history; explicit reset required"},
        503: {"description": "Gateway activity ledger unavailable"},
    },
)
async def gateway_activity_stream(
    request: Request,
    cursor: str | None = Query(default=None, min_length=1, max_length=1000, description="Resume after this tenant-bound ledger cursor"),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID", min_length=1, max_length=1000),
    limit: int = Query(default=100, ge=1, le=500, description="Maximum canonical records per SSE frame"),
) -> GatewayActivityStreamResponse:
    """Backfill all retained canonical events, then follow new commits in order.

    Last-Event-ID takes precedence over the initial query cursor on reconnect.
    With neither, start at the retention floor. Connections last at most 30
    seconds of iteration before reauthentication; blocked sends time out after
    5 seconds. Heartbeats show transport liveness, not producer attestation.
    Legacy alerts and LLM cost spans have no ledger ordinal and are excluded.
    """
    if str(getattr(request.state, "auth_method", "") or "") in {"", "anonymous", "no_auth"}:
        raise HTTPException(status_code=401, detail="Authentication required for gateway activity streaming")
    tenant_id = require_request_tenant_id(request)
    deadline = time.monotonic() + _STREAM_MAX_SECONDS
    try:
        first_page = await anyio.to_thread.run_sync(_read_stream_page, tenant_id, last_event_id or cursor, limit)
    except GatewayActivityCursorExpiredError as exc:
        raise HTTPException(
            status_code=410,
            detail={
                "message": "Gateway activity cursor is older than retained history",
                "retention_floor_ordinal": exc.retention_floor_ordinal,
            },
        ) from exc
    except GatewayActivityCursorError as exc:
        raise HTTPException(status_code=400, detail="Invalid gateway activity cursor") from exc
    except Exception as exc:  # noqa: BLE001 - do not expose backend exception text
        raise HTTPException(status_code=503, detail="Gateway activity storage unavailable") from exc
    return GatewayActivityStreamResponse(
        _stream_activity(tenant_id, first_page, limit, deadline),
        ping=10,
        send_timeout=5,
        headers={"Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no"},
    )


@router.get(
    "/gateway/feed",
    tags=["gateway"],
    dependencies=[_dep("read")],
    response_model=GatewayFeedResponseModel,
)
async def gateway_feed(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500, description="Max fused events to return (1-500)"),
    cursor: str | None = Query(default=None, max_length=1000, description="Opaque tenant-bound ledger cursor"),
) -> dict[str, Any]:
    """Unified, time-ordered fleet event feed for the active tenant.

    Fuses tool-call authorization decisions (allowed / blocked), data-filter /
    DLP redaction events, and recent LLM calls into one normalized stream with
    per-agent attribution. Reference-only and redaction-safe: every event is
    metadata (timestamp, agent, action class, target, short non-secret detail);
    no raw arguments, responses, or credential values are returned.
    """
    tenant_id = require_request_tenant_id(request)
    # Direct unit calls invoke the handler without FastAPI resolving Query.
    if not isinstance(cursor, str):
        cursor = None
    try:
        (
            page,
            older_omitted,
            compatibility_alerts,
            llm_records,
            ledger_available,
            observability_available,
        ) = await _gather_durable_feed_inputs_async(
            tenant_id,
            cursor=cursor,
            limit=limit,
        )
    except GatewayActivityCursorExpiredError as exc:
        raise HTTPException(
            status_code=410,
            detail={
                "message": "Gateway activity cursor is older than retained history",
                "retention_floor_ordinal": exc.retention_floor_ordinal,
            },
        ) from exc
    except GatewayActivityCursorError as exc:
        raise HTTPException(status_code=400, detail="Invalid gateway activity cursor") from exc
    except GatewayFeedLedgerUnavailableError as exc:
        raise HTTPException(status_code=503, detail="Gateway activity storage unavailable") from exc
    payload = await anyio.to_thread.run_sync(
        partial(
            build_gateway_feed,
            tenant_id=tenant_id,
            alerts=[*page.events, *compatibility_alerts],
            llm_records=llm_records,
            limit=limit,
        )
    )
    payload["next_cursor"] = page.next_cursor
    payload["has_more"] = page.has_more
    payload["source"] = (
        "gateway_activity_ledger"
        if ledger_available and (page.latest_ordinal > 0 or not compatibility_alerts)
        else "degraded_single_process"
    )
    payload["completeness"] = _feed_completeness(
        page,
        older_omitted=older_omitted,
        supplemental_event_count=len(compatibility_alerts) + len(llm_records),
        ledger_available=ledger_available,
        observability_available=observability_available,
    )
    payload["health"] = _feed_health_from_metrics(await anyio.to_thread.run_sync(_load_tenant_transport_metrics, tenant_id))
    return payload


@router.get(
    "/gateway/feed/kpis",
    tags=["gateway"],
    dependencies=[_dep("read")],
    response_model=GatewayFeedKpisModel,
)
async def gateway_feed_kpis(request: Request) -> dict[str, Any]:
    """KPI header rollup for the gateway live feed.

    Returns ``calls_today``, ``blocked_today``, ``shadow_ai_blocked`` (shadow /
    undeclared-agent + shadow-MCP-server blocks), ``data_filters_applied``, and
    ``uptime_seconds`` (only when the proxy reports it — never fabricated).
    """
    tenant_id = require_request_tenant_id(request)
    window_end = datetime.now(timezone.utc)
    window_start = window_end.replace(hour=0, minute=0, second=0, microsecond=0)
    (
        alerts,
        llm_records,
        summary,
        compatibility_count,
        llm_truncated,
        ledger_available,
        observability_available,
    ) = await _gather_kpi_inputs_async(
        tenant_id,
        start=window_start,
        end=window_end,
    )
    uptime_seconds = await anyio.to_thread.run_sync(_load_tenant_uptime, tenant_id)
    payload = await anyio.to_thread.run_sync(
        partial(
            build_gateway_feed_kpis,
            tenant_id=tenant_id,
            alerts=alerts,
            llm_records=llm_records,
            uptime_seconds=uptime_seconds,
        )
    )
    payload["tool_calls_authorized"] += summary.tool_calls_authorized
    payload["blocked_today"] += summary.blocked
    payload["shadow_ai_blocked"] += summary.shadow_blocked
    payload["data_filters_applied"] += summary.data_filters
    payload["calls_today"] += summary.tool_calls_authorized + summary.blocked
    for assurance, count in summary.producer_assurance_counts.items():
        payload["producer_assurance_counts"][assurance] += count
    payload["producer_assurance"] = producer_assurance_rollup(payload["producer_assurance_counts"])
    partial_reasons: list[str] = []
    if not ledger_available:
        partial_reasons.append("ledger_unavailable")
    if summary.retention_floor_ordinal > 1:
        partial_reasons.append("retention_floor_advanced")
    if compatibility_count:
        partial_reasons.append("legacy_unordered_sources")
    if llm_truncated:
        partial_reasons.append("observability_window_limit")
    if not observability_available:
        partial_reasons.append("observability_unavailable")
    exact = not partial_reasons
    payload["source"] = (
        "gateway_activity_ledger"
        if ledger_available and (summary.latest_ordinal > 0 or compatibility_count == 0)
        else "degraded_single_process"
    )
    payload["completeness"] = {
        "status": "complete" if exact else "partial",
        "reasons": partial_reasons,
        "retention_floor_ordinal": summary.retention_floor_ordinal,
        "latest_ordinal": summary.latest_ordinal,
    }
    payload["window"] = {
        "start": window_start.isoformat(),
        "end": window_end.isoformat(),
        "timezone": "UTC",
        "exact": exact,
    }
    payload["health"] = _feed_health_from_metrics(await anyio.to_thread.run_sync(_load_tenant_transport_metrics, tenant_id))
    return payload
