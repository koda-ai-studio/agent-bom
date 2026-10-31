"""Scalar current-estate reads using source revisions instead of graph payloads."""

from collections.abc import Callable
from typing import Any

from agent_bom.api.finding_read_context import cached_read, read_once


def count_current_nodes(
    store: Any, tenant: str, entity_type: str, identity_for: Callable, rotation_error: Callable, attempts: int
) -> tuple[str, int]:
    """Return a scalar and the current-estate ID derived from source revisions.

    A later graph read materializes that same ID. Evidence churn within the
    request refuses a mixed view instead of making a stale count look current.
    """
    pinned = cached_read((f"current-graph:{id(store)}", tenant))
    reader = getattr(store._graph_store, "count_snapshot_nodes", None)
    if pinned is not None or not callable(reader):
        scan, _, _, count, _ = store.page_nodes(tenant_id=tenant, entity_types={entity_type}, limit=1)
        return scan, count
    for _ in range(attempts):
        summaries, _, jobs, fingerprint = store._evidence_state(tenant, request_scoped=False)
        store._check_count_evidence(tenant, fingerprint)
        if not summaries and store._graph_store.snapshot_identity(tenant_id=tenant, for_paging=True)[0]:
            scan, _, _, count, _ = store._graph_store.page_nodes(tenant_id=tenant, entity_types={entity_type}, limit=1)
            return scan, count
        with store._lock.shared():
            if live := store._cached_live_id(tenant, fingerprint):
                _, _, _, count, _ = store._projection_store.page_nodes(tenant_id=tenant, scan_id=live, entity_types={entity_type}, limit=1)
                read_once((f"current-graph:{id(store)}", tenant), lambda: store._pin(live))
                return live, count
        if jobs is None:
            jobs = [store._job_store.get(row["job_id"], tenant_id=tenant) for row in summaries]
        jobs = [job for job in jobs if job is not None and job.tenant_id == tenant]
        _, revisions, _ = store._available_sources(tenant, jobs)
        count = reader(tenant_id=tenant, scan_ids=[scan for scan, revision in revisions if revision], entity_type=entity_type)
        if store._revisions(tenant, (scan for scan, _ in revisions)) != revisions:
            continue
        if store._evidence_state(tenant, request_scoped=False)[3] != fingerprint:
            continue
        read_once((f"current-count-evidence:{id(store)}", tenant), lambda: (fingerprint, revisions))
        identity = identity_for(fingerprint, revisions)
        return identity, count
    raise rotation_error()
