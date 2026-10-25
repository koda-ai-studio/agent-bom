"""Time-bounded keyset reads for graph evidence, without retained-feed totals."""

from __future__ import annotations

import heapq
from datetime import datetime, timezone
from typing import Any, Iterable

from agent_bom.api.storage.runtime_records import RuntimeObservationRecord, _observation_from_json

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def epoch_us(value: str) -> int | None:
    """Exact UTC microseconds; malformed and untimed evidence is not a timed event."""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            return None
        delta = moment.astimezone(timezone.utc) - _EPOCH
        return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    except (ValueError, TypeError, OverflowError, AttributeError):
        return None


def _validate(
    window_start: str, window_end: str, limit: int, surfaces: tuple[str, ...], before: tuple[str, str] | None
) -> tuple[int, int, tuple[int, str] | None]:
    start, end = epoch_us(window_start), epoch_us(window_end)
    if start is None or end is None or start > end:
        raise ValueError("Observation window requires ordered timezone-aware bounds")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("Observation window limit must be between 1 and 500")
    if not surfaces or len(surfaces) > 8 or any(not isinstance(s, str) or not 0 < len(s) <= 80 for s in surfaces):
        raise ValueError("Observation window requires bounded surface names")
    cursor = None
    if before is not None:
        if not isinstance(before, tuple) or len(before) != 2 or not isinstance(before[1], str) or not 0 < len(before[1]) <= 512:
            raise ValueError("Invalid observation window cursor")
        tick = epoch_us(before[0])
        if tick is None:
            raise ValueError("Invalid observation window cursor time")
        cursor = (tick, before[1])
    return start, end, cursor


def memory_window(
    rows: Iterable[RuntimeObservationRecord],
    *,
    window_start: str,
    window_end: str,
    surfaces: tuple[str, ...],
    limit: int = 500,
    before: tuple[str, str] | None = None,
) -> list[RuntimeObservationRecord]:
    start, end, cursor = _validate(window_start, window_end, limit, surfaces, before)
    selected = (
        (tick, row.observation_id, row)
        for row in rows
        if row.surface in surfaces
        and (tick := epoch_us(row.observed_at)) is not None
        and start <= tick <= end
        and (cursor is None or (tick, row.observation_id) < cursor)
    )
    return [row for _, _, row in heapq.nlargest(limit, selected, key=lambda item: item[:2])]


def sql_window(
    conn: Any,
    tenant_id: str,
    *,
    window_start: str,
    window_end: str,
    surfaces: tuple[str, ...],
    limit: int = 500,
    before: tuple[str, str] | None = None,
    postgres: bool = False,
) -> list[RuntimeObservationRecord]:
    start, end, cursor = _validate(window_start, window_end, limit, surfaces, before)
    marker = "%s" if postgres else "?"
    if postgres:
        tick = (
            "CASE WHEN observed_at ~ '(Z|[+-][0-9]{2}:[0-9]{2})$' "
            "AND pg_input_is_valid(observed_at, 'timestamp with time zone') "
            "THEN (EXTRACT(EPOCH FROM observed_at::timestamptz) * 1000000)::bigint END"
        )
        surface = "data::jsonb->>'surface'"
    else:
        conn.create_function("agent_bom_epoch_us", 1, epoch_us, deterministic=True)
        tick, surface = "agent_bom_epoch_us(observed_at)", "json_extract(data, '$.surface')"
    slots = ",".join(marker for _ in surfaces)
    seek = f"AND (tick, observation_id) < ({marker}, {marker})" if cursor else ""
    params = (tenant_id, *surfaces, start, end, *(cursor or ()), limit)
    rows = conn.execute(
        f"WITH candidates AS (SELECT data, observation_id, {tick} AS tick FROM runtime_observations "  # nosec B608
        f"WHERE tenant_id = {marker} AND {surface} IN ({slots})) "
        f"SELECT data FROM candidates WHERE tick >= {marker} AND tick <= {marker} {seek} "
        f"ORDER BY tick DESC, observation_id DESC LIMIT {marker}",
        params,
    ).fetchall()
    return [_observation_from_json(row[0]) for row in rows]
