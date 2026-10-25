"""Route trace evidence into storage, unified findings and the graph build."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any, Callable, TypeVar

from agent_bom.api.gateway_activity_store import get_gateway_activity_store
from agent_bom.api.models import JobStatus
from agent_bom.api.runtime_event_store import RuntimeEventStore, get_runtime_event_store
from agent_bom.api.trace_collection.normalized_events import (
    coverage_summary,
    normalize_otlp_body,
    normalized_from_native_span,
    persist_normalized_events,
    signals_by_span,
    trace_window,
)
from agent_bom.api.trace_collection.runtime_evidence import load_runtime_window
from agent_bom.api.trace_collection.trace_findings import (
    FindingSink,
    shadow_findings,
    signal_findings,
    write_findings,
)
from agent_bom.core.experimental import is_enabled
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
    # Name candidates cannot establish a vulnerable package behind an exact
    # tool reference. Keep them in the ingest response, never in graph signals.
    events, rejected = normalize_otlp_body(body, tenant_id=tenant_id, signals={key: frozenset(value) for key, value in signals.items()})
    persisted = persist_normalized_events(store or get_runtime_event_store(), events)
    findings = signal_findings(tenant_id, events)
    return _summary(events, len(findings), write_findings(tenant_id, findings, sink), persisted=persisted, rejected=rejected)


def record_native_evidence(spans: Iterable[Mapping[str, Any]], *, tenant_id: str, sink: FindingSink | None) -> dict[str, Any]:
    """Findings for screened signals on natively imported spans (already persisted by the importer)."""
    events = [event for span in spans if (event := normalized_from_native_span(span, tenant_id=tenant_id)) is not None]
    findings = signal_findings(tenant_id, events)
    return _summary(events, len(findings), write_findings(tenant_id, findings, sink))


_Store = TypeVar("_Store")


def _available_store(factory: Callable[[], _Store], kind: str, failures: list[str]) -> _Store | None:
    try:
        return factory()
    except Exception:  # broad-except: unavailable stores remain explicit missing evidence
        _logger.warning("Runtime evidence store unavailable for graph build", exc_info=False)
        failures.append(f"{kind}_store_unavailable")
        return None


def with_trace_events(report_json: dict[str, Any], tenant_id: str, *, store: RuntimeEventStore | None = None) -> dict[str, Any]:
    """Overlay persisted runtime evidence through one tenant-scoped, bounded window.

    Trace providers retain their experimental opt-in. Runtime and gateway records
    are metadata-only evidence already accepted by authenticated ingest routes.
    """
    traces = is_enabled("traces")
    anchor = report_json.get("scan_timestamp") or report_json.get("observed_at") or report_json.get("generated_at")
    window_start, window_end = trace_window(anchor)
    base: dict[str, Any] = {"window_start": window_start, "window_end": window_end}
    failures: list[str] = []
    runtime = _available_store(lambda: store or get_runtime_event_store(), "runtime", failures)
    gateway = _available_store(get_gateway_activity_store, "gateway", failures)
    window = load_runtime_window(runtime, gateway, tenant_id, window_start=window_start, window_end=window_end, traces=traces)
    window.failures.extend(failures)
    result = dict(report_json)
    if window.activity or window.truncated or window.failures:
        result["runtime_activity_events"] = {
            **base,
            "events": window.activity,
            "load_truncated": window.truncated,
            "load_failures": sorted(set(window.failures)),
        }
    if traces and (window.traces or window.truncated or window.failures):
        result["runtime_trace_events"] = {
            **base,
            "events": window.traces,
            "load_truncated": window.truncated,
            "load_failed": "runtime_store_unavailable" in window.failures,
        }
    return result


def emit_shadow_findings(graph: UnifiedGraph, tenant_id: str, sink: FindingSink | None) -> int:
    if not is_enabled("traces"):
        return 0
    shadow = getattr(getattr(graph, "runtime_trace_projection", None), "shadow", None)
    return write_findings(tenant_id, shadow_findings(tenant_id, shadow), sink) if shadow else 0
