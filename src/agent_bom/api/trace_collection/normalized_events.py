"""Persist and read canonical trace events in tenant-scoped runtime storage.

Every trace source is normalized into ``NormalizedTraceEvent`` before storage;
the graph reads these events, never vendor payloads. Imported Langfuse and
LangSmith spans carry the event on their ``imported_trace`` observation, and
OTLP JSON spans are stored as ``normalized_trace`` observations. Tenant always
comes from the authenticated request or connection scope.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api.runtime_event_store import RuntimeEventStore
from agent_bom.api.storage.runtime_records import RuntimeObservationRecord
from agent_bom.canonical_ids import canonical_id
from agent_bom.runtime.normalized_trace import (
    NORMALIZED_ATTRIBUTE,
    NormalizedTraceEvent,
    coverage_by_source,
    from_otlp_span,
    iter_otlp_spans,
)

NORMALIZED_SURFACE = "normalized_trace"
IMPORTED_SURFACE = "imported_trace"
WINDOW_DAYS = 30
MAX_WINDOW_EVENTS = 20_000
_PAGE = 500
# Shield response detectors -> canonical trace signals.
DETECTOR_SIGNALS = {
    "credential_leak": "secret",
    "pii_leak": "pii",
    "response_inspector": "prompt_injection",
    "vector_db_injection": "prompt_injection",
    "argument_analyzer": "prompt_injection",
}


def _value(item: object, key: str) -> str:
    raw = item.get(key) if isinstance(item, Mapping) else getattr(item, key, "")
    return str(raw or "")


def signals_by_span(content_findings: Iterable[object]) -> dict[tuple[str, str], frozenset[str]]:
    """Map screened ``(trace_id, span_id)`` to canonical signals; unknown detectors add none."""
    signals: dict[tuple[str, str], set[str]] = {}
    for finding in content_findings:
        signal = DETECTOR_SIGNALS.get(_value(finding, "detector").removeprefix("shield_"))
        if signal:
            signals.setdefault((_value(finding, "trace_id"), _value(finding, "span_id")), set()).add(signal)
    return {key: frozenset(value) for key, value in signals.items()}


def normalize_otlp_body(
    body: Mapping[str, Any], *, tenant_id: str, signals: Mapping[tuple[str, str], frozenset[str]] | None = None
) -> tuple[list[NormalizedTraceEvent], int]:
    """Normalize every OTLP span; return events and the count rejected as invalid."""
    events: list[NormalizedTraceEvent] = []
    rejected = 0
    for span, resource in iter_otlp_spans(body):
        key = (str(span.get("traceId") or ""), str(span.get("spanId") or ""))
        try:
            events.append(
                from_otlp_span(span, tenant_id=tenant_id, resource_attributes=resource, signals=(signals or {}).get(key, frozenset()))
            )
        except ValueError:
            rejected += 1
    return events, rejected


def stamp_page_signals(spans: Iterable[object], signals: Mapping[tuple[str, str], frozenset[str]]) -> None:
    """Add screened signals to the canonical event a native span already carries."""
    for span in spans:
        if not isinstance(span, dict) or not isinstance(span.get("attributes"), list):
            continue
        extra = signals.get((str(span.get("traceId") or ""), str(span.get("spanId") or "")))
        for attribute in span["attributes"] if extra else []:
            value = attribute.get("value") if isinstance(attribute, dict) else None
            if not isinstance(value, dict) or attribute.get("key") != NORMALIZED_ATTRIBUTE:
                continue
            try:
                payload = json.loads(value["stringValue"])
            except (KeyError, TypeError, ValueError):
                continue
            payload["signals"] = sorted({*payload.get("signals", []), *(extra or ())})
            value["stringValue"] = json.dumps(payload, sort_keys=True)


def normalized_from_native_span(span: Mapping[str, Any], *, tenant_id: str) -> NormalizedTraceEvent | None:
    """Read the canonical event a native connector span carries; bind the caller's tenant."""
    for attribute in span.get("attributes") or []:
        if isinstance(attribute, dict) and attribute.get("key") == NORMALIZED_ATTRIBUTE:
            try:
                payload = json.loads(attribute["value"]["stringValue"])
                return NormalizedTraceEvent.from_dict(payload).bind_tenant(tenant_id)
            except (KeyError, TypeError, ValueError):
                return None
    return None


def _record(event: NormalizedTraceEvent) -> RuntimeObservationRecord:
    trace = event.source_trace_id or event.source_span_id
    return RuntimeObservationRecord(
        tenant_id=event.tenant_id,
        observation_id=canonical_id(NORMALIZED_SURFACE, event.tenant_id, event.source, trace, event.source_span_id),
        session_id=f"{event.source}-trace:{trace}"[:512],
        observed_at=event.started_at or "",
        source=event.source,
        surface=NORMALIZED_SURFACE,
        event_type="normalized_span",
        severity="unknown",
        verdict="error" if event.status == "error" else "success",
        tool_name=event.tool_name or "",
        agent_name=event.agent_name or "",
        trace_id=event.source_trace_id[:512],
        span_id=event.source_span_id[:512],
        metadata={"normalized": event.to_dict()},
    )


def persist_normalized_events(store: RuntimeEventStore, events: list[NormalizedTraceEvent]) -> int:
    """Store timed events; untimed spans cannot be windowed and are reported, not stored."""
    return store.put_observations_batch([_record(event) for event in events if event.started_at]) if events else 0


def trace_window(anchor: object) -> tuple[str, str]:
    """A fixed window ending at the snapshot's own timestamp, so rebuilds do not drift."""
    moment = None
    if isinstance(anchor, str) and anchor:
        try:
            moment = datetime.fromisoformat(anchor.replace("Z", "+00:00"))
        except ValueError:
            moment = None
    if moment is None or moment.tzinfo is None:
        moment = datetime.now(timezone.utc)
    end = moment.astimezone(timezone.utc)
    return (end - timedelta(days=WINDOW_DAYS)).isoformat(), end.isoformat()


def load_window_events(
    store: RuntimeEventStore, tenant_id: str, *, window_start: str, window_end: str
) -> tuple[list[dict[str, Any]], bool]:
    """Read canonical events for one tenant inside the window, newest first, bounded."""
    events: list[dict[str, Any]] = []
    start = datetime.fromisoformat(window_start)
    for surface in (IMPORTED_SURFACE, NORMALIZED_SURFACE):
        offset = 0
        while len(events) < MAX_WINDOW_EVENTS:
            page = store.query_observations(tenant_id, limit=_PAGE, offset=offset, surface=surface)["observations"]
            for record in page:
                normalized = record.metadata.get("normalized") if record.tenant_id == tenant_id else None
                if isinstance(normalized, dict) and normalized.get("tenant_id") == tenant_id:
                    events.append(normalized)
            if len(page) < _PAGE or _before(page[-1].observed_at, start):
                break
            offset += _PAGE
    return events[:MAX_WINDOW_EVENTS], len(events) >= MAX_WINDOW_EVENTS


def _before(observed_at: str, start: datetime) -> bool:
    try:
        moment = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return moment.tzinfo is not None and moment < start


def coverage_summary(events: list[NormalizedTraceEvent]) -> dict[str, dict[str, Any]]:
    return {source: {"events": entry["events"], "missing": entry["missing"]} for source, entry in coverage_by_source(events).items()}
