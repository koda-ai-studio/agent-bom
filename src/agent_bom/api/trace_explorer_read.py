"""Bounded assembly of the trace explorer across durable read stores."""

from collections.abc import Iterable
from itertools import islice
from typing import Any, cast

from agent_bom.api import trace_explorer
from agent_bom.api.runtime_event_store import RuntimeEventStore
from agent_bom.api.trace_inventory_correlation import correlate_inventory_observations
from agent_bom.api.trace_inventory_paths import attach_inventory_paths


def assemble_trace_explorer(
    store: RuntimeEventStore,
    tenant_id: str,
    *,
    limit: int,
    offset: int = 0,
    scan_id: str | None,
    feed: dict[str, Any],
    finding_rows: Iterable[dict[str, Any]],
    graph_store: Any,
    **filters: Any,
) -> dict[str, object]:
    bounded_limit = max(1, min(limit, 200))
    findings = list(islice(finding_rows, bounded_limit))
    sessions = [session.to_dict() for session in store.list_sessions(tenant_id, limit=bounded_limit, offset=0)]
    page = store.query_observations(tenant_id, limit=bounded_limit, offset=offset, **filters)
    observations = [observation.to_dict() for observation in page["observations"]]
    session_ids = {row["session_id"] for row in observations}
    sessions = [row for row in sessions if row["session_id"] in session_ids]
    feed_included = offset == 0 and not any(value is not None for value in filters.values())
    bindings = {}
    if scan_id:
        bindings = correlate_inventory_observations(graph_store, tenant_id=tenant_id, scan_id=scan_id, observations=observations)
        bindings = attach_inventory_paths(graph_store, tenant_id=tenant_id, scan_id=scan_id, bindings=bindings)
    payload = trace_explorer.build_trace_explorer_payload(
        inventory_bindings=bindings,
        tenant_id=tenant_id,
        feed_events=cast(list[dict[str, Any]], feed.get("events", []) if feed_included else []),
        findings=findings,
        sessions=sessions,
        observations=observations,
        limit=bounded_limit,
    )
    payload.update(
        retained_total=page["total"],
        source_counts=page["sources"],
        offset=offset,
        limit=bounded_limit,
        has_more=offset + len(observations) < page["total"],
        feed_included=feed_included,
        counts_scope="matching_retained_observations",
    )
    return payload
