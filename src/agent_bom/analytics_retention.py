"""Shared analytics growth caps for local mirrors and runtime observations."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom import config
from agent_bom.core.settings import env_int
from agent_bom.db.local_analytics_sqlite import page_stats

_DEFAULT_ANALYTICS_MAX_EVENTS = 50_000
_DEFAULT_ANALYTICS_MAX_PACKAGES = 500_000
_DEFAULT_ANALYTICS_MAX_FINDINGS = 250_000
_DEFAULT_ANALYTICS_MAX_TRACE_REVISIONS = 250_000


class _ObservationCapConnection(Protocol):
    def execute(self, query: str, params: Any = ()) -> Any: ...


def _runtime_observation_queries(placeholder: str) -> tuple[str, str, str]:
    if placeholder == "%s":
        return (
            "SELECT COUNT(*) FROM runtime_observations WHERE tenant_id = %s",
            """
            SELECT observation_id FROM runtime_observations
            WHERE tenant_id = %s
            ORDER BY observed_at ASC
            LIMIT %s
            """,
            "DELETE FROM runtime_observations WHERE tenant_id = %s AND observation_id = %s",
        )
    if placeholder == "?":
        return (
            "SELECT COUNT(*) FROM runtime_observations WHERE tenant_id = ?",
            """
            SELECT observation_id FROM runtime_observations
            WHERE tenant_id = ?
            ORDER BY observed_at ASC
            LIMIT ?
            """,
            "DELETE FROM runtime_observations WHERE tenant_id = ? AND observation_id = ?",
        )
    raise ValueError("unsupported SQL placeholder")


def analytics_max_events() -> int:
    """Return the retained analytics event cap. ``<= 0`` disables pruning."""
    raw = os.environ.get("AGENT_BOM_ANALYTICS_MAX_EVENTS")
    if raw is None:
        try:
            from agent_bom.config import ANALYTICS_MAX_EVENTS

            return int(ANALYTICS_MAX_EVENTS)
        except (ImportError, TypeError, ValueError):
            return _DEFAULT_ANALYTICS_MAX_EVENTS
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_ANALYTICS_MAX_EVENTS


def _env_cap(name: str, default: int) -> int:
    return env_int(name, default, on_invalid="default")


def analytics_max_packages() -> int:
    """Return the retained local package-row cap. ``<= 0`` disables it."""
    try:
        from agent_bom.config import ANALYTICS_MAX_PACKAGES

        default = int(ANALYTICS_MAX_PACKAGES)
    except (ImportError, TypeError, ValueError):
        default = _DEFAULT_ANALYTICS_MAX_PACKAGES
    return _env_cap("AGENT_BOM_ANALYTICS_MAX_PACKAGES", default)


def analytics_max_findings() -> int:
    """Return the retained local finding-row cap. ``<= 0`` disables it."""
    try:
        from agent_bom.config import ANALYTICS_MAX_FINDINGS

        default = int(ANALYTICS_MAX_FINDINGS)
    except (ImportError, TypeError, ValueError):
        default = _DEFAULT_ANALYTICS_MAX_FINDINGS
    return _env_cap("AGENT_BOM_ANALYTICS_MAX_FINDINGS", default)


def analytics_max_trace_revisions() -> int:
    """Return the per-tenant imported-trace revision cap. ``<= 0`` disables it."""
    try:
        from agent_bom.config import ANALYTICS_MAX_TRACE_REVISIONS

        default = int(ANALYTICS_MAX_TRACE_REVISIONS)
    except (ImportError, TypeError, ValueError):
        default = _DEFAULT_ANALYTICS_MAX_TRACE_REVISIONS
    return _env_cap("AGENT_BOM_ANALYTICS_MAX_TRACE_REVISIONS", default)


def analytics_max_run_age_days() -> int:
    """Return the whole-run age cap (days) for the local scan mirror. ``<= 0`` disables it."""
    return _env_cap("AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS", int(config.ANALYTICS_MAX_RUN_AGE_DAYS))


def analytics_max_bytes() -> int:
    """Return the live-bytes cap for the local scan mirror file. ``<= 0`` disables it."""
    return _env_cap("AGENT_BOM_ANALYTICS_MAX_BYTES", int(config.ANALYTICS_MAX_BYTES))


def local_mirror_limits() -> dict[str, int]:
    return {
        "scan_runs": analytics_max_events(),
        "findings": analytics_max_findings(),
        "packages": analytics_max_packages(),
        "run_age_days": analytics_max_run_age_days(),
        "bytes": analytics_max_bytes(),
    }


def local_mirror_over_limit(counts: dict[str, int], limits: dict[str, int], *, oldest_run_age_days: float | None, live_bytes: int) -> bool:
    over_rows = any(limits[key] > 0 and counts[key] > limits[key] for key in ("scan_runs", "findings", "packages"))
    over_age = limits["run_age_days"] > 0 and oldest_run_age_days is not None and oldest_run_age_days > limits["run_age_days"]
    return over_rows or over_age or (limits["bytes"] > 0 and live_bytes > limits["bytes"])


def _parse_generated_at(value: Any) -> datetime | None:
    try:
        stamp = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=timezone.utc)


def run_age_days(generated_at: Any, now: datetime | None = None) -> float | None:
    """Age of a run timestamp in days, or None when it cannot be parsed."""
    stamp = _parse_generated_at(generated_at)
    if stamp is None:
        return None
    return ((now or datetime.now(timezone.utc)) - stamp).total_seconds() / 86_400


def plan_local_scan_prune(
    conn: sqlite3.Connection,
    *,
    max_events: int | None = None,
    max_packages: int | None = None,
    max_findings: int | None = None,
    max_age_days: int | None = None,
    max_bytes: int | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Return the oldest whole runs that must be removed to satisfy every cap.

    The newest run is always retained, even if that single run exceeds a cap.
    This keeps the local mirror useful while making the over-limit state
    visible to operators. The byte cap compares the file's live bytes (pages
    in use, not the freelist) and attributes them to runs by row count, and
    a run whose timestamp cannot be parsed is never aged out.
    """
    event_cap = analytics_max_events() if max_events is None else max_events
    package_cap = analytics_max_packages() if max_packages is None else max_packages
    finding_cap = analytics_max_findings() if max_findings is None else max_findings
    age_cap = analytics_max_run_age_days() if max_age_days is None else max_age_days
    byte_cap = analytics_max_bytes() if max_bytes is None else max_bytes
    rows = conn.execute(
        """
        SELECT run_id, package_rows, finding_rows, generated_at
        FROM scan_runs
        ORDER BY generated_at ASC, recorded_at ASC, rowid ASC
        """
    ).fetchall()
    if len(rows) <= 1:
        return []

    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=age_cap) if age_cap > 0 else None
    live_bytes = page_stats(conn)["live_bytes"] if byte_cap > 0 else 0
    weights = [int(row[1]) + int(row[2]) + 1 for row in rows]
    total_weight = sum(weights)
    weight_left = total_weight
    package_total = sum(int(row[1]) for row in rows)
    finding_total = sum(int(row[2]) for row in rows)
    stale: list[str] = []
    remaining = len(rows)
    for row, weight in zip(rows[:-1], weights):
        over_events = event_cap > 0 and remaining > event_cap
        over_packages = package_cap > 0 and package_total > package_cap
        over_findings = finding_cap > 0 and finding_total > finding_cap
        generated = _parse_generated_at(row[3])
        over_age = cutoff is not None and generated is not None and generated < cutoff
        over_bytes = byte_cap > 0 and live_bytes * weight_left / total_weight > byte_cap
        if not (over_events or over_packages or over_findings or over_age or over_bytes):
            break
        stale.append(str(row[0]))
        remaining -= 1
        package_total -= int(row[1])
        finding_total -= int(row[2])
        weight_left -= weight
    return stale


def prune_local_scan_runs(
    conn: sqlite3.Connection,
    *,
    max_events: int | None = None,
    max_packages: int | None = None,
    max_findings: int | None = None,
    max_age_days: int | None = None,
    max_bytes: int | None = None,
) -> int:
    """Drop oldest whole scan runs when any configured mirror cap is exceeded."""
    run_ids = plan_local_scan_prune(
        conn,
        max_events=max_events,
        max_packages=max_packages,
        max_findings=max_findings,
        max_age_days=max_age_days,
        max_bytes=max_bytes,
    )
    if not run_ids:
        return 0
    conn.executemany("DELETE FROM scan_runs WHERE run_id = ?", ((run_id,) for run_id in run_ids))
    return len(run_ids)


def prune_runtime_observations_for_tenant(
    conn: _ObservationCapConnection,
    tenant_id: str,
    *,
    max_events: int | None = None,
    placeholder: str = "?",
) -> int:
    """Drop oldest runtime observations for one tenant when over the cap."""
    cap = analytics_max_events() if max_events is None else max_events
    if cap <= 0:
        return 0
    count_query, stale_query, delete_query = _runtime_observation_queries(placeholder)
    count_row = conn.execute(
        count_query,
        (tenant_id,),
    ).fetchone()
    count = int(count_row[0])
    if count <= cap:
        return 0
    excess = count - cap
    stale = conn.execute(
        stale_query,
        (tenant_id, excess),
    ).fetchall()
    if not stale:
        return 0
    observation_ids = [str(row[0]) for row in stale]
    for observation_id in observation_ids:
        conn.execute(delete_query, (tenant_id, observation_id))
    return len(observation_ids)
