"""Lifecycle state for one read: durable where the store has it, folded from retained scans otherwise."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any
from uuid import uuid4

from agent_bom.api.finding_job_metadata import scan_evidence_authority_key
from agent_bom.api.finding_lifecycle_fold import FindingState, RowsForJob, replay_lifecycle
from agent_bom.api.storage import finding_lifecycle as durable

# Sits with the finding walk's own 50k row bound; the response warns when reached.
RESOLVED_READ_LIMIT = 50_000


@dataclass(slots=True)
class LifecycleRead:
    states: list[FindingState]
    load_payloads: Callable[[list[FindingState]], None] = field(default=lambda _states: None)


def _migrate_ticket_links(pairs: list[tuple[str, str]], tenant_id: str) -> None:
    """A ticket filed before projects joined finding identity stays linked to each project's finding."""
    if not pairs:
        return
    from agent_bom.ticketing.connection_store import get_ticketing_store

    store = get_ticketing_store()
    renamed: dict[str, list[str]] = {}
    for reported, project_id in pairs:
        renamed.setdefault(reported, []).append(project_id)
    reported_ids = sorted(renamed)
    for start in range(0, len(reported_ids), 1000):
        batch = set(reported_ids[start : start + 1000])
        for link in store.list_ticket_links_for_findings(tenant_id, batch, limit=10_000):
            for project_id in renamed[link.dedupe_key]:
                store.claim_ticket_link(replace(link, id=str(uuid4()), dedupe_key=project_id))


def ensure_backfilled(store: Any, tenant_id: str, jobs: Callable[[], list[Any]]) -> None:
    """Seed durable state from retained scans once; every step is idempotent, so racing readers converge."""
    with store.finding_lifecycle_session(tenant_id, write=False) as session:
        if durable.backfilled(session, tenant_id):
            return
    for job in sorted(jobs(), key=scan_evidence_authority_key):
        with store.finding_lifecycle_session(tenant_id) as session:
            durable.apply_job_lifecycle(session, store.finding_lifecycle_dialect, job)
    with store.finding_lifecycle_session(tenant_id) as session:
        pairs = durable.renamed_findings(session, tenant_id)
    _migrate_ticket_links(pairs, tenant_id)
    with store.finding_lifecycle_session(tenant_id) as session:
        durable.mark_backfilled(session, tenant_id)


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


def lifecycle_read(
    store: Any, tenant_id: str, jobs: Callable[[], list[Any]], rows_for_job: RowsForJob, *, since: str | None, include_resolved: bool
) -> LifecycleRead:
    if not callable(getattr(store, "finding_lifecycle_session", None)):
        return LifecycleRead(replay_lifecycle(jobs(), rows_for_job))
    ensure_backfilled(store, tenant_id, jobs)
    with store.finding_lifecycle_session(tenant_id, write=False) as session:
        states = durable.live_states(session, tenant_id)
        if include_resolved:
            states.extend(durable.resolved_states(session, tenant_id, since, RESOLVED_READ_LIMIT))

    def load_payloads(wanted: list[FindingState]) -> None:
        with store.finding_lifecycle_session(tenant_id, write=False) as session:
            durable.attach_payloads(session, tenant_id, wanted)

    return LifecycleRead(states, load_payloads)
