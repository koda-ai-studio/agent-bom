"""Unpinned current-estate reads over Postgres treat evidence churn during assembly as retryable."""

from __future__ import annotations

import pytest
from starlette.exceptions import HTTPException

from tests.test_postgres_migrated_graph_parity import migrated_fresh_database, pytestmark  # noqa: F401

TENANT = "assembly-tenant"


def _record(jobs, graph_store, *nodes: str) -> None:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
    from tests.api.test_scan_job_sla_history import job

    scan = job(8, tenant=TENANT, target="repo-a", findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=TENANT, created_at=scan.completed_at)
    for name in nodes:
        graph.add_node(UnifiedNode(id=name, entity_type=EntityType.PACKAGE, label=name))
    token = set_current_tenant(TENANT)
    try:
        graph_store.save_graph(graph)
    finally:
        reset_current_tenant(token)
    jobs.put(scan)


@pytest.mark.parametrize("replays,expected", [(1, 200), (100, 503)])
def test_postgres_source_replaced_during_assembly_never_answers_409(migrated_fresh_database, replays, expected):  # noqa: F811
    from agent_bom.api.current_graph import CurrentGraphStore
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.api.store import InMemoryJobStore

    jobs, graph_store = InMemoryJobStore(), PostgresGraphStore()
    _record(jobs, graph_store, "package-a")
    load = graph_store.load_graph
    done: list[int] = []

    def replaying(*args, **kwargs):
        graph = load(*args, **kwargs)
        if len(done) < replays:
            done.append(1)
            _record(jobs, graph_store, f"package-replay-{len(done)}")
        return graph

    graph_store.load_graph = replaying  # type: ignore[method-assign]
    store = CurrentGraphStore(graph_store, jobs)
    token = set_current_tenant(TENANT)
    try:
        if expected == 200:
            assert set(store.load_graph(tenant_id=TENANT).nodes) == {"package-replay-1"}
            return
        with pytest.raises(HTTPException) as exc:
            store.load_graph(tenant_id=TENANT)
    finally:
        reset_current_tenant(token)
    assert exc.value.status_code == 503
    assert exc.value.headers == {"Retry-After": "1"}


def test_postgres_current_count_matches_ordered_merge_and_rls(migrated_fresh_database, monkeypatch):  # noqa: F811
    from agent_bom.api.current_graph import CurrentGraphStore
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.graph import EntityType
    from tests.api.test_current_graph_counts import record

    jobs, backing = InMemoryJobStore(), PostgresGraphStore()
    store = CurrentGraphStore(backing, jobs)
    estate = store, backing, jobs
    token = set_current_tenant(TENANT)
    try:
        record(estate, 7, "a", [("shared", EntityType.AGENT), ("conflict", EntityType.PACKAGE)], tenant=TENANT)
        record(estate, 8, "b", [("shared", EntityType.AGENT), ("conflict", EntityType.AGENT), ("new", EntityType.AGENT)], tenant=TENANT)
        with monkeypatch.context() as patch:
            patch.setattr(backing, "load_graph", lambda **kw: pytest.fail("count decoded graph payloads"))
            identity, count = store.count_nodes(tenant_id=TENANT, entity_type="agent")
        graph = store.load_graph(tenant_id=TENANT)
        assert count == 2 == len(graph.nodes_by_type(EntityType.AGENT))
        assert identity == graph.scan_id
    finally:
        reset_current_tenant(token)
    token = set_current_tenant("different-tenant")
    try:
        assert (
            backing.count_snapshot_nodes(
                tenant_id=TENANT, scan_ids=[scan.job_id for scan in jobs.list_all(tenant_id=TENANT)], entity_type="agent"
            )
            == 0
        )
    finally:
        reset_current_tenant(token)
