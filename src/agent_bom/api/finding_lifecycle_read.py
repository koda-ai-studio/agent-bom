"""Lifecycle state for one read."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.api.finding_collection import collect_scan_findings
from agent_bom.api.finding_lifecycle_fold import FindingState, replay_lifecycle
from agent_bom.api.storage import finding_lifecycle as durable

_EVIDENCE_CACHE_LIMIT = 5_000
# Sits with the finding walk's own 50k row bound; the response warns when reached.
RESOLVED_READ_LIMIT = 50_000


@dataclass(slots=True)
class LifecycleRead:
    states: list[FindingState]
    load_payloads: Callable[[list[FindingState]], None] = field(default=lambda _states: None)


def purge_tenant_lifecycle(store: Any, tenant_id: str) -> int:
    if not callable(getattr(store, "finding_lifecycle_session", None)):
        return 0
    with store.finding_lifecycle_session(tenant_id) as session:
        return durable.purge_tenant(session, tenant_id)


def resolved_history_truncated(store: Any, tenant_id: str, since: str | None) -> bool:
    if not callable(getattr(store, "finding_lifecycle_session", None)):
        return False
    with store.finding_lifecycle_session(tenant_id, write=False) as session:
        return durable.resolved_exceeds(session, tenant_id, since, RESOLVED_READ_LIMIT)


def _no_projection(_job: Any) -> list[dict[str, Any]]:
    return []


def _with_retained_reports(states: list[FindingState], retained: list[FindingState]) -> list[FindingState]:
    """A partly seeded tenant: retained reports decide state, durable rows keep any earlier first_seen."""
    durable_rows = {(state.scope_hash, state.finding_key): state for state in states}
    for state in retained:
        earlier = durable_rows.pop((state.scope_hash, state.finding_key), None)
        if earlier is not None:
            state.first_seen = min(state.first_seen, earlier.first_seen)
    return [*durable_rows.values(), *retained]


def lifecycle_read(
    store: Any, tenant_id: str, jobs: Callable[[], list[Any]], *, since: str | None, include_resolved: bool
) -> LifecycleRead:
    """State for one read; its cost follows the findings it serves, not the scans retained.

    Three bounded cases: a SQL store reads durable rows and runs no scan projection.
    A store with no table folds each retained report in memory, reusing a job's
    evidence when it holds the jobs itself. While a tenant's older scans await the
    maintenance tick, a read folds only their finding streams, once per read; it
    writes nothing, and a report with no stream stays unstamped until the tick.
    """
    if not callable(getattr(store, "finding_lifecycle_session", None)):
        cache = getattr(store, "finding_evidence_cache", None)
        if cache is not None and len(cache) > _EVIDENCE_CACHE_LIMIT:
            cache.clear()
        return LifecycleRead(replay_lifecycle(jobs(), collect_scan_findings, cache=cache))
    with store.finding_lifecycle_session(tenant_id, write=False) as session:
        states = durable.live_states(session, tenant_id)
        if include_resolved:
            states.extend(durable.resolved_states(session, tenant_id, since, RESOLVED_READ_LIMIT))
        seeded = durable.backfilled(session, tenant_id)
        pending = not seeded and bool(durable.pending_job_ids(session, store.finding_lifecycle_dialect, tenant_id, 1))
    if pending:
        states = _with_retained_reports(states, replay_lifecycle(jobs(), _no_projection))

    def load_payloads(wanted: list[FindingState]) -> None:
        with store.finding_lifecycle_session(tenant_id, write=False) as session:
            durable.attach_payloads(session, tenant_id, wanted)

    return LifecycleRead(states, load_payloads)
