"""Scalar counts preserve current graph scope without reconstructing its payloads."""

import pytest
from starlette.exceptions import HTTPException

from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from tests.api.test_scan_job_sla_history import job

TENANT = "count-tenant"


@pytest.fixture
def estate(tmp_path):
    backing = SQLiteGraphStore(tmp_path / "graph.db")
    jobs = InMemoryJobStore()
    return CurrentGraphStore(backing, jobs), backing, jobs


def record(estate, month, target, nodes, *, partial=False, tenant=TENANT):
    _, backing, jobs = estate
    scan = job(month, tenant=tenant, target=target, findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "partial" if partial else "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=tenant, created_at=scan.completed_at)
    for name, kind in nodes:
        graph.add_node(UnifiedNode(id=name, entity_type=kind, label=name))
    backing.save_graph(graph)
    jobs.put(scan)
    return scan.job_id


def test_count_avoids_graph_payloads_and_matches_projection(estate, monkeypatch):
    store, backing, _ = estate
    record(estate, 7, "a", [("shared", EntityType.AGENT), ("conflict", EntityType.PACKAGE)])
    record(estate, 8, "b", [("shared", EntityType.AGENT), ("conflict", EntityType.AGENT), ("new", EntityType.AGENT)])
    record(estate, 9, "c", [("foreign", EntityType.AGENT)], tenant="foreign")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_materialize", lambda *a: pytest.fail("scalar count built graph and paths"))
        patch.setattr(backing, "load_graph", lambda **kw: pytest.fail("scalar count decoded payloads"))
        identity, total = store.count_nodes(tenant_id=TENANT, entity_type="agent")
    graph = store.load_graph(tenant_id=TENANT)
    assert total == 2 == len(graph.nodes_by_type(EntityType.AGENT))
    assert identity == graph.scan_id
    assert store.count_nodes(tenant_id="foreign", entity_type="agent")[1] == 1


def test_partial_and_missing_snapshots_keep_prior_evidence(estate):
    store, backing, _ = estate
    record(estate, 7, "a", [("old", EntityType.AGENT)])
    recent = record(estate, 8, "a", [("partial", EntityType.AGENT)], partial=True)
    assert store.count_nodes(tenant_id=TENANT, entity_type="agent")[1] == 2
    backing.delete_snapshot(tenant_id=TENANT, scan_id=recent)
    assert store.count_nodes(tenant_id=TENANT, entity_type="agent")[1] == 1
    record(estate, 9, "a", [])
    assert store.count_nodes(tenant_id=TENANT, entity_type="agent")[1] == 0


@pytest.mark.parametrize("moves", [1, 100])
def test_count_retries_replaced_source_and_bounds_churn(estate, monkeypatch, moves):
    store, backing, _ = estate
    record(estate, 7, "a", [("old", EntityType.AGENT)])
    original = backing.count_snapshot_nodes
    calls = []

    def changing(**kwargs):
        count = original(**kwargs)
        if len(calls) < moves:
            calls.append(1)
            record(estate, 7, "a", [(f"new-{i}", EntityType.AGENT) for i in range(3)])
        return count

    monkeypatch.setattr(backing, "count_snapshot_nodes", changing)
    if moves == 1:
        assert store.count_nodes(tenant_id=TENANT, entity_type="agent")[1] == 3
    else:
        with pytest.raises(HTTPException) as error:
            store.count_nodes(tenant_id=TENANT, entity_type="agent")
        assert error.value.status_code == 503
        assert len(calls) == 3


def test_graph_first_count_keeps_pinned_generation(estate):
    store, _, _ = estate
    record(estate, 7, "a", [("old", EntityType.AGENT)])
    with finding_read_scope():
        graph = store.load_graph(tenant_id=TENANT)
        record(estate, 8, "a", [])
        assert store.count_nodes(tenant_id=TENANT, entity_type="agent") == (graph.scan_id, 1)
    assert store.count_nodes(tenant_id=TENANT, entity_type="agent")[1] == 0


def test_count_first_refuses_to_mix_new_graph_evidence(estate):
    store, _, _ = estate
    record(estate, 7, "a", [("old", EntityType.AGENT)])
    with finding_read_scope():
        identity, count = store.count_nodes(tenant_id=TENANT, entity_type="agent")
        assert count == 1
        record(estate, 8, "a", [])
        with pytest.raises(HTTPException) as error:
            store.load_graph(tenant_id=TENANT)
        assert error.value.status_code == 503
    assert store.load_graph(tenant_id=TENANT).scan_id != identity


def test_posture_uses_scalar_count(estate, monkeypatch):
    from agent_bom.api.routes.compliance_routes import common

    store, _, _ = estate
    record(estate, 7, "a", [("agent", EntityType.AGENT)])
    monkeypatch.setattr(common, "_get_graph_store", lambda: store)
    monkeypatch.setattr(store, "_materialize", lambda *a: pytest.fail("posture rebuilt graph"))
    assert common.estate_agent_count(TENANT)["total"] == 1


def test_warm_count_pins_materialized_generation(estate):
    store, _, _ = estate
    record(estate, 7, "a", [("old", EntityType.AGENT)])
    initial = store.load_graph(tenant_id=TENANT)
    with finding_read_scope():
        assert store.count_nodes(tenant_id=TENANT, entity_type="agent") == (initial.scan_id, 1)
        record(estate, 8, "a", [])
        assert store.load_graph(tenant_id=TENANT).scan_id == initial.scan_id
    assert store.count_nodes(tenant_id=TENANT, entity_type="agent")[1] == 0


def test_count_retries_job_authority_change_during_query(estate, monkeypatch):
    store, backing, _ = estate
    record(estate, 7, "a", [("old", EntityType.AGENT)])
    original = backing.count_snapshot_nodes
    calls = []

    def changing(**kwargs):
        count = original(**kwargs)
        if not calls:
            calls.append(1)
            record(estate, 8, "a", [])
        return count

    monkeypatch.setattr(backing, "count_snapshot_nodes", changing)
    assert store.count_nodes(tenant_id=TENANT, entity_type="agent")[1] == 0
