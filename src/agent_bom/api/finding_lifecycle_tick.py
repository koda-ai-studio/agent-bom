"""Maintenance tick that seeds durable finding lifecycle from retained scans, outside any read."""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any
from uuid import uuid4

from agent_bom.api.storage import finding_lifecycle as durable
from agent_bom.api.stores import _get_store
from agent_bom.api.tenant_worker import tenant_bound_context

_BACKFILL_BATCH_JOBS = 16
_TICK_BUDGET_SECONDS = 20.0
_TICK_TENANTS = 100


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


def _backfill_tenant(store: Any, tenant_id: str, deadline: float) -> tuple[int, bool]:
    """Fold a tenant's scans from before this table, in small commits; ``(jobs folded, finished)``."""
    folded = 0
    while time.monotonic() < deadline:
        with store.finding_lifecycle_session(tenant_id, write=False) as session:
            pending = durable.pending_job_ids(session, store.finding_lifecycle_dialect, tenant_id, _BACKFILL_BATCH_JOBS)
        if not pending:
            with store.finding_lifecycle_session(tenant_id, write=False) as session:
                pairs = durable.renamed_findings(session, tenant_id)
            _migrate_ticket_links(pairs, tenant_id)
            with store.finding_lifecycle_session(tenant_id) as session:
                durable.mark_backfilled(session, tenant_id)
            return folded, True
        for job_id in pending:
            job = store.get(job_id, tenant_id)
            if job is not None:
                with store.finding_lifecycle_session(tenant_id) as session:
                    durable.apply_job_lifecycle(session, store.finding_lifecycle_dialect, job)
            folded += 1
    return folded, False


def run_finding_lifecycle_tick(*, budget_seconds: float = _TICK_BUDGET_SECONDS) -> int:
    """Seed durable state from retained scans, outside any read; returns jobs handled and tenants finished.

    Replicas can run this together: a repeated job is a no-op and writers of one
    scope serialize. Reads answer from the retained reports until it finishes.
    """
    store = _get_store()
    list_tenants = getattr(store, "finding_lifecycle_unbackfilled_tenants", None)
    if not callable(list_tenants):
        return 0
    deadline = time.monotonic() + budget_seconds
    handled = 0
    for tenant_id in list_tenants(_TICK_TENANTS):
        if time.monotonic() >= deadline:
            break
        with tenant_bound_context(tenant_id):
            folded, finished = _backfill_tenant(store, tenant_id, deadline)
        handled += folded + int(finished)
    return handled
