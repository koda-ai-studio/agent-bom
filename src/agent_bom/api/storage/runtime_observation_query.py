"""Bounded retained-activity reads. SQL values are always bound parameters."""

from __future__ import annotations

from collections import Counter
from typing import Any

from agent_bom.api.storage.runtime_records import RuntimeObservationRecord, RuntimeSessionRecord, _observation_from_json, _session_from_json

FILTER_FIELDS = {"session_id", "source", "agent_name", "connection_id"}


def session_keys(session_ids: list[str]) -> list[str]:
    if len(session_ids) > 500 or any(not isinstance(key, str) or not key or len(key) > 512 for key in session_ids):
        raise ValueError("Session lookup requires at most 500 valid identities")
    return list(dict.fromkeys(session_ids))


def sql_sessions(conn: Any, tenant_id: str, session_ids: list[str], *, postgres: bool = False) -> list[RuntimeSessionRecord]:
    keys = session_keys(session_ids)
    if not keys:
        return []
    marker = "%s" if postgres else "?"
    placeholders = ",".join(marker for _ in keys)
    rows = conn.execute(
        f"SELECT data FROM runtime_sessions WHERE tenant_id={marker} AND session_id IN ({placeholders}) "  # nosec B608
        "ORDER BY last_seen DESC, session_id DESC",
        (tenant_id, *keys),
    ).fetchall()
    return [_session_from_json(row[0]) for row in rows]


def order_sessions(rows: list[RuntimeSessionRecord]) -> list[RuntimeSessionRecord]:
    """Newest activity first, then session id; matches the SQL session reads."""
    return sorted(rows, key=lambda row: (row.last_seen, row.session_id), reverse=True)


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
    # validate_query allowlists every field; values and paging are bound parameters.
    counts = conn.execute(
        f"SELECT {field('source')}, COUNT(*) FROM runtime_observations WHERE {where} GROUP BY {field('source')}",  # nosec B608
        params,
    ).fetchall()
    rows = conn.execute(
        f"SELECT data FROM runtime_observations WHERE {where} "  # nosec B608
        f"ORDER BY observed_at DESC, observation_id DESC LIMIT {marker} OFFSET {marker}",
        (*params, limit, offset),
    ).fetchall()
    return {
        "observations": [_observation_from_json(row[0]) for row in rows],
        "total": sum(row[1] for row in counts),
        "sources": {row[0] or "unknown": row[1] for row in counts},
    }
