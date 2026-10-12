"""Bounded retained-activity reads. SQL values are always bound parameters."""

from __future__ import annotations

from collections import Counter
from typing import Any

from agent_bom.api.storage.runtime_records import RuntimeObservationRecord, _observation_from_json

FILTER_FIELDS = {"session_id", "source", "agent_name", "connection_id"}


def validate_query(limit: int, offset: int, filters: dict[str, Any]) -> dict[str, str]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("Observation limit must be between 1 and 500")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Observation offset must be nonnegative")
    if set(filters) - FILTER_FIELDS or any(
        value is not None and (not isinstance(value, str) or not 0 < len(value) <= 512) for value in filters.values()
    ):
        raise ValueError("Invalid observation filter")
    return {key: value for key, value in filters.items() if value is not None}


def memory_observation_page(rows: list[RuntimeObservationRecord], *, limit: int, offset: int, **filters: Any) -> dict[str, Any]:
    query = validate_query(limit, offset, filters)
    selected = [
        row
        for row in rows
        if all((row.metadata.get(key) if key == "connection_id" else getattr(row, key)) == value for key, value in query.items())
    ]
    selected.sort(key=lambda row: (row.observed_at, row.observation_id), reverse=True)
    return {
        "observations": selected[offset : offset + limit],
        "total": len(selected),
        "sources": dict(Counter(row.source for row in selected)),
    }


def sql_observation_page(conn: Any, tenant_id: str, *, limit: int, offset: int, postgres: bool = False, **filters: Any) -> dict[str, Any]:
    query = validate_query(limit, offset, filters)
    marker = "%s" if postgres else "?"

    def field(key: str) -> str:
        if key == "session_id":
            return "session_id"
        if postgres:
            return "data::jsonb->'metadata'->>'connection_id'" if key == "connection_id" else f"data::jsonb->>'{key}'"
        return f"json_extract(data, '$.{'metadata.' if key == 'connection_id' else ''}{key}')"

    clauses = [f"tenant_id = {marker}", *(f"{field(key)} = {marker}" for key in query)]
    params = (tenant_id, *query.values())
    where = " AND ".join(clauses)
    # Live reads: totals describe the matching retained projection at query time,
    # not an immutable provider snapshot or an unbounded execution history.
    counts = conn.execute(
        f"SELECT {field('source')}, COUNT(*) FROM runtime_observations WHERE {where} GROUP BY {field('source')}", params
    ).fetchall()
    rows = conn.execute(
        f"SELECT data FROM runtime_observations WHERE {where} "
        f"ORDER BY observed_at DESC, observation_id DESC LIMIT {marker} OFFSET {marker}",
        (*params, limit, offset),
    ).fetchall()
    return {
        "observations": [_observation_from_json(row[0]) for row in rows],
        "total": sum(row[1] for row in counts),
        "sources": {row[0] or "unknown": row[1] for row in counts},
    }
