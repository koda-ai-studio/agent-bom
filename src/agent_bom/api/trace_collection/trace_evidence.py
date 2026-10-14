"""Route trace evidence into storage, unified findings and the graph build."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.api.models import JobStatus
from agent_bom.api.runtime_event_store import RuntimeEventStore, get_runtime_event_store
from agent_bom.api.trace_collection.normalized_events import (
    coverage_summary,
    load_window_events,
    normalize_otlp_body,
    normalized_from_native_span,
    persist_normalized_events,
    signals_by_span,
    trace_window,
)
from agent_bom.api.trace_collection.trace_findings import (
    FindingSink,
    shadow_findings,
    signal_findings,
    vulnerable_call_findings,
    write_findings,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.runtime.normalized_trace import NormalizedTraceEvent

_logger = logging.getLogger(__name__)


def vulnerable_inventory(jobs: Iterable[Any]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Packages and servers with known CVEs from the tenant's completed scans."""
    packages: dict[str, set[str]] = defaultdict(set)
    servers: dict[str, set[str]] = defaultdict(set)
    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        for blast in job.result.get("blast_radius", []):
            cve_id = blast.get("vulnerability_id", "")
            if blast.get("package"):
                packages[blast["package"]].update([cve_id] if cve_id else [])
            for server in blast.get("affected_servers", []):
                name = server if isinstance(server, str) else server.get("name", "")
                if name:
                    servers[name].update([cve_id] if cve_id else [])
    return {key: sorted(value) for key, value in packages.items()}, {key: sorted(value) for key, value in servers.items()}


def _summary(events: list[NormalizedTraceEvent], findings: int, written: int, **counts: int) -> dict[str, Any]:
    return {
        "events": len(events),
        "untimed": sum(1 for event in events if not event.started_at),
        "exact_refs": sum(1 for event in events if event.match_method == "exact"),
        "findings": findings,
        "findings_persisted": written,
        "coverage": coverage_summary(events),
        **counts,
    }


def record_otlp_evidence(
    body: Mapping[str, Any],
    *,
    tenant_id: str,
    flagged: list[Any],
    content_findings: Iterable[object],
    sink: FindingSink | None,
    store: RuntimeEventStore | None = None,
) -> dict[str, Any]:
    """Normalize every OTLP span, persist the canonical events and emit their findings."""
    signals = {key: set(value) for key, value in signals_by_span(content_findings).items()}
    for flag in flagged:
        signals.setdefault((flag.trace.trace_id, flag.trace.span_id), set()).add("vulnerable_tool_call")
    events, rejected = normalize_otlp_body(body, tenant_id=tenant_id, signals={key: frozenset(value) for key, value in signals.items()})
    persisted = persist_normalized_events(store or get_runtime_event_store(), events)
    findings = signal_findings(tenant_id, events) + vulnerable_call_findings(tenant_id, flagged, events)
    return _summary(events, len(findings), write_findings(tenant_id, findings, sink), persisted=persisted, rejected=rejected)


def record_native_evidence(spans: Iterable[Mapping[str, Any]], *, tenant_id: str, sink: FindingSink | None) -> dict[str, Any]:
    """Findings for screened signals on natively imported spans (already persisted by the importer)."""
    events = [event for span in spans if (event := normalized_from_native_span(span, tenant_id=tenant_id)) is not None]
    findings = signal_findings(tenant_id, events)
    return _summary(events, len(findings), write_findings(tenant_id, findings, sink))


def with_trace_events(report_json: dict[str, Any], tenant_id: str, *, store: RuntimeEventStore | None = None) -> dict[str, Any]:
    """Overlay the tenant's canonical trace events for the snapshot window on a shallow copy."""
    anchor = report_json.get("scan_timestamp") or report_json.get("observed_at") or report_json.get("generated_at")
    window_start, window_end = trace_window(anchor)
    payload: dict[str, Any] = {"events": [], "window_start": window_start, "window_end": window_end}
    try:
        events, truncated = load_window_events(
            store or get_runtime_event_store(), tenant_id, window_start=window_start, window_end=window_end
        )
    except Exception:  # broad-except: a trace-store outage is recorded on the graph instead of failing the snapshot
        _logger.warning("Runtime trace events unavailable for graph build", exc_info=False)
        return {**report_json, "runtime_trace_events": {**payload, "load_failed": True}}
    if not events:
        return report_json
    payload.update(events=events, load_truncated=truncated)
    return {**report_json, "runtime_trace_events": payload}


def emit_shadow_findings(graph: UnifiedGraph, tenant_id: str, sink: FindingSink | None) -> int:
    shadow = getattr(getattr(graph, "runtime_trace_projection", None), "shadow", None)
    return write_findings(tenant_id, shadow_findings(tenant_id, shadow), sink) if shadow else 0
