"""Gateway window summaries and bounded graph-evidence reads."""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from agent_bom.api.storage.runtime_observation_window import _validate, epoch_us
from agent_bom.runtime.gateway_events import GATEWAY_ALLOWED_EVENT_TYPES, GATEWAY_BLOCKED_EVENT_TYPES, GATEWAY_DATA_FILTER_EVENT_TYPES
from agent_bom.runtime.profile_resolution import classify_profile_shadow_reason


def register_activity_clock(conn: Any) -> None:
    """Register the deterministic UTC clock before reading or writing its index."""
    conn.create_function("agent_bom_epoch_us", 1, epoch_us, deterministic=True)


def ensure_activity_time_index(conn: Any) -> None:
    register_activity_clock(conn)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_activity_window ON gateway_activity_events"
        "(tenant_id, agent_bom_epoch_us(event_timestamp), event_id)"
    )


def memory_activity_window(
    rows: Iterable[Any], *, window_start: str, window_end: str, limit: int = 500, before: tuple[str, str] | None = None
) -> list[Any]:
    start, end, cursor = _validate(window_start, window_end, limit, ("gateway",), before)
    selected = (
        (tick, row.event_id, row)
        for row in rows
        if (tick := epoch_us(row.event_timestamp)) is not None
        and start <= tick <= end
        and (cursor is None or (tick, row.event_id) < cursor)
    )
    return [row for _, _, row in heapq.nlargest(limit, selected, key=lambda item: item[:2])]


def sql_activity_window(
    conn: Any,
    tenant_id: str,
    *,
    window_start: str,
    window_end: str,
    limit: int = 500,
    before: tuple[str, str] | None = None,
    postgres: bool = False,
) -> list[str]:
    start, end, cursor = _validate(window_start, window_end, limit, ("gateway",), before)
    marker = "%s" if postgres else "?"
    tick = "event_timestamp" if postgres else "agent_bom_epoch_us(event_timestamp)"
    bounds: tuple[int | datetime, int | datetime]
    seek_values: tuple[int | datetime, str] | tuple[()]
    if postgres:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        bounds = (epoch + timedelta(microseconds=start), epoch + timedelta(microseconds=end))
        seek_values = (epoch + timedelta(microseconds=cursor[0]), cursor[1]) if cursor else ()
    else:
        register_activity_clock(conn)
        bounds, seek_values = (start, end), cursor or ()
    seek = f"AND (tick, event_id) < ({marker}, {marker})" if cursor else ""
    rows = conn.execute(
        f"WITH candidates AS (SELECT data, event_id, {tick} AS tick FROM gateway_activity_events "  # nosec B608
        f"WHERE tenant_id = {marker}) SELECT data FROM candidates "
        f"WHERE tick >= {marker} AND tick <= {marker} {seek} ORDER BY tick DESC, event_id DESC LIMIT {marker}",
        (tenant_id, *bounds, *seek_values, limit),
    ).fetchall()
    return [row[0] for row in rows]


@dataclass(frozen=True)
class GatewayActivityWindowSummary:
    tenant_id: str
    start: str
    end: str
    tool_calls_authorized: int
    blocked: int
    shadow_blocked: int
    data_filters: int
    retention_floor_ordinal: int
    latest_ordinal: int
    producer_assurance_counts: dict[str, int] = field(default_factory=lambda: {"unknown": 0, "caller_asserted": 0})


_SHADOW_REASON_MARKERS = (
    "undeclared",
    "shadow",
    "unknown_agent",
    "unknown agent",
    "unregistered",
    "unknown-agent",
)


def _is_shadow_reason(reason_code: str) -> bool:
    canonical = classify_profile_shadow_reason(reason_code)
    if canonical is not None:
        return canonical
    normalized = reason_code.lower()
    return any(marker in normalized for marker in _SHADOW_REASON_MARKERS)


def _window_summary(
    tenant_id: str,
    *,
    start: str,
    end: str,
    event_rows: list[tuple[str, str, int, str]],
    floor: int,
    latest: int,
) -> GatewayActivityWindowSummary:
    authorized = sum(count for event_type, _reason, count, _assurance in event_rows if event_type in GATEWAY_ALLOWED_EVENT_TYPES)
    blocked = sum(count for event_type, _reason, count, _assurance in event_rows if event_type in GATEWAY_BLOCKED_EVENT_TYPES)
    data_filters = sum(count for event_type, _reason, count, _assurance in event_rows if event_type in GATEWAY_DATA_FILTER_EVENT_TYPES)
    shadow_blocked = sum(
        count
        for event_type, reason, count, _assurance in event_rows
        if event_type in GATEWAY_BLOCKED_EVENT_TYPES and _is_shadow_reason(reason)
    )
    return GatewayActivityWindowSummary(
        tenant_id=tenant_id,
        start=start,
        end=end,
        tool_calls_authorized=authorized,
        blocked=blocked,
        shadow_blocked=shadow_blocked,
        data_filters=data_filters,
        retention_floor_ordinal=floor,
        latest_ordinal=latest,
        producer_assurance_counts={
            assurance: sum(
                count
                for event_type, _reason, count, value in event_rows
                if value == assurance
                and event_type in GATEWAY_ALLOWED_EVENT_TYPES | GATEWAY_BLOCKED_EVENT_TYPES | GATEWAY_DATA_FILTER_EVENT_TYPES
            )
            for assurance in ("unknown", "caller_asserted")
        },
    )
