"""Project local session spans onto a discovery graph with the shared trace projection."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.trace_projection import TraceProjectionResult, project_trace_events
from agent_bom.runtime.normalized_trace import NORMALIZED_ATTRIBUTE, NormalizedTraceEvent

LOCAL_TENANT = "local"


def normalized_events(spans: Iterable[dict[str, Any]], tenant_id: str = LOCAL_TENANT) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for span in spans:
        for item in span.get("attributes") or []:
            if item.get("key") != NORMALIZED_ATTRIBUTE:
                continue
            try:
                event = NormalizedTraceEvent.from_dict(json.loads(item["value"]["stringValue"])).bind_tenant(tenant_id)
            except (KeyError, TypeError, ValueError):
                break
            events.append(event.to_dict())
            break
    return events


def project_session_spans(
    graph: UnifiedGraph, spans: Iterable[dict[str, Any]], *, window_start: datetime, window_end: datetime
) -> TraceProjectionResult:
    return project_trace_events(
        graph,
        normalized_events(spans, graph.tenant_id or LOCAL_TENANT),
        tenant_id=graph.tenant_id or LOCAL_TENANT,
        window_start=window_start.isoformat(),
        window_end=window_end.isoformat(),
    )
