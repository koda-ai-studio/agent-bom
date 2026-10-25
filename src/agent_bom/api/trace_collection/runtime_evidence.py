"""One tenant/time-window budget across stored traces, runtime observations and gateway activity."""

from __future__ import annotations

import heapq
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from agent_bom.api.gateway_activity_store import GatewayActivityRecord, GatewayActivityStore
from agent_bom.api.runtime_event_store import RuntimeEventStore
from agent_bom.api.storage.runtime_observation_window import epoch_us
from agent_bom.api.storage.runtime_records import RuntimeObservationRecord
from agent_bom.api.trace_collection.normalized_events import IMPORTED_SURFACE, NORMALIZED_SURFACE

MAX_WINDOW_EVENTS = 20_000
PAGE_SIZE = 500


@dataclass
class RuntimeEvidenceWindow:
    traces: list[dict[str, Any]] = field(default_factory=list)
    activity: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    failures: list[str] = field(default_factory=list)
    examined: int = 0


def _runtime_activity(record: RuntimeObservationRecord) -> dict[str, Any]:
    context = record.metadata.get("graph_context")
    context = context if isinstance(context, dict) else {}
    return {
        "tenant_id": record.tenant_id,
        "event_id": record.observation_id,
        "observed_at": record.observed_at,
        "source": record.source,
        "surface": record.surface,
        "session_id": record.session_id,
        "trace_id": record.trace_id,
        "event_type": record.event_type,
        "verdict": record.verdict,
        "agent_name": record.agent_name,
        "target_name": record.tool_name,
        "timestamp_basis": record.metadata.get("timestamp_basis", "reported"),
        "producer_assurance": "caller_asserted",
        **{key: context.get(key, "") for key in ("agent_ref", "target_ref", "account_ref", "provider")},
    }


def _gateway_activity(record: GatewayActivityRecord) -> dict[str, Any]:
    return {
        "tenant_id": record.tenant_id,
        "event_id": record.event_id,
        "observed_at": record.event_timestamp,
        "source": record.source_id,
        "surface": "gateway",
        "session_id": record.session_id,
        "trace_id": record.trace_id,
        "event_type": record.event_type,
        "verdict": record.decision,
        "agent_ref": record.agent_id,
        "agent_name": record.agent_id,
        "target_ref": record.tool,
        "target_name": record.tool,
        "upstream_ref": record.upstream,
        "record_digest": record.event_digest,
        "producer_assurance": record.producer_assurance,
        "timestamp_basis": "reported",
        "account_ref": "",
        "provider": "",
    }


def _pages(
    store: Any, tenant: str, start: str, end: str, result: RuntimeEvidenceWindow, *, gateway: bool, traces: bool
) -> Iterator[RuntimeObservationRecord | GatewayActivityRecord]:
    before = None
    page_size = min(PAGE_SIZE, MAX_WINDOW_EVENTS + 1)
    surfaces = ("runtime", "proxy", "gateway") + ((IMPORTED_SURFACE, NORMALIZED_SURFACE) if traces else ())
    while True:
        try:
            kwargs = {"window_start": start, "window_end": end, "limit": page_size, "before": before}
            rows = store.window_activity(tenant, **kwargs) if gateway else store.window_observations(tenant, surfaces=surfaces, **kwargs)
        except Exception:  # broad-except: unavailable evidence becomes an explicit graph receipt; no raw exception is exposed
            result.failures.append("gateway_store_unavailable" if gateway else "runtime_store_unavailable")
            return
        for record in rows:
            yield record
        if len(rows) < page_size:
            return
        last = rows[-1]
        before = (last.event_timestamp, last.event_id) if gateway else (last.observed_at, last.observation_id)


def _order(record: RuntimeObservationRecord | GatewayActivityRecord) -> tuple[int, str, str]:
    if isinstance(record, GatewayActivityRecord):
        return epoch_us(record.event_timestamp) or 0, "gateway", record.event_id
    return epoch_us(record.observed_at) or 0, "runtime", record.observation_id


def load_runtime_window(
    runtime: RuntimeEventStore | None,
    gateway: GatewayActivityStore | None,
    tenant_id: str,
    *,
    window_start: str,
    window_end: str,
    traces: bool,
) -> RuntimeEvidenceWindow:
    """Merge newest-first keyset streams; apply one cap with lookahead, never retained-feed totals."""
    result = RuntimeEvidenceWindow()
    streams = [
        _pages(store, tenant_id, window_start, window_end, result, gateway=is_gateway, traces=traces)
        for store, is_gateway in ((runtime, False), (gateway, True))
        if store is not None
    ]
    for row in heapq.merge(*streams, key=_order, reverse=True):
        result.examined += 1
        if result.examined > MAX_WINDOW_EVENTS:
            result.truncated = True
            break
        if row.tenant_id != tenant_id:
            result.failures.append("tenant_rejected")
            continue
        if isinstance(row, GatewayActivityRecord):
            result.activity.append(_gateway_activity(row))
        elif row.surface in (IMPORTED_SURFACE, NORMALIZED_SURFACE):
            normalized = row.metadata.get("normalized")
            if isinstance(normalized, dict) and normalized.get("tenant_id") == tenant_id:
                result.traces.append(normalized)
            else:
                result.failures.append("invalid_trace_event")
        else:
            result.activity.append(_runtime_activity(row))
    return result
