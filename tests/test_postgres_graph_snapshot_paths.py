"""Snapshot path index on both stores: rank order, distinct routes, tenant isolation, purge."""

from __future__ import annotations

import os
from contextlib import contextmanager
from uuid import uuid4

import pytest

from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.path_derivation import _derived_attack_paths
from tests.graph.test_snapshot_paths import shared_server_estate


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    if request.param == "sqlite":
        yield SQLiteGraphStore(tmp_path / "graph.db")
        return
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL is required for live Postgres snapshot path checks")
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_graph import PostgresGraphStore

    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        yield PostgresGraphStore(pool=pool)
    finally:
        pool.close()


@contextmanager
def tenant_scope(tenant: str):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        yield
    finally:
        reset_current_tenant(token)


def _two_routes(tenant: str, scan: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan, tenant_id=tenant)
    for node_id, entity_type in (
        ("agent:a", EntityType.AGENT),
        ("server:x", EntityType.SERVER),
        ("server:y", EntityType.SERVER),
        ("data:crown", EntityType.DATA_STORE),
    ):
        graph.add_node(UnifiedNode(id=node_id, entity_type=entity_type, label=node_id))
    for via, risk in (("server:x", 80.0), ("server:y", 60.0)):
        graph.add_edge(UnifiedEdge(source="agent:a", target=via, relationship=RelationshipType.USES))
        graph.add_edge(UnifiedEdge(source=via, target="data:crown", relationship=RelationshipType.CAN_ACCESS))
        graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target="data:crown",
                hops=["agent:a", via, "data:crown"],
                edges=["uses", "can_access"],
                composite_risk=risk,
                reachability="likely",
            )
        )
    return graph


def _rows_visible_without_tenant_predicate(store, scan: str) -> int | None:
    from agent_bom.api.graph_store import SQLiteGraphStore

    if isinstance(store, SQLiteGraphStore):
        return None
    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(store._pool) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM graph_attack_paths WHERE scan_id = %s", (scan,)).fetchone()[0])


def test_distinct_routes_persist_and_tenants_stay_isolated(store) -> None:
    scan = f"paths-{uuid4().hex[:10]}"
    tenant_a, tenant_b = f"ta-{uuid4().hex[:8]}", f"tb-{uuid4().hex[:8]}"
    with tenant_scope(tenant_a):
        store.save_graph(_two_routes(tenant_a, scan))
        stored = store.snapshot_attack_paths(tenant_id=tenant_a, scan_id=scan)
        own_rows = _rows_visible_without_tenant_predicate(store, scan)
    with tenant_scope(tenant_b):
        assert store.snapshot_attack_paths(tenant_id=tenant_b, scan_id=scan) is None
        foreign_rows = _rows_visible_without_tenant_predicate(store, scan)
    if own_rows is not None:
        # Row-level security alone (no tenant_id predicate) hides tenant A's rows.
        assert (own_rows, foreign_rows) == (2, 0)

    assert stored is not None
    assert [path.hops for path in stored.paths] == [["agent:a", "server:x", "data:crown"], ["agent:a", "server:y", "data:crown"]]

    with tenant_scope(tenant_a):
        assert store.delete_snapshot(tenant_id=tenant_a, scan_id=scan) > 0
        assert store.snapshot_attack_paths(tenant_id=tenant_a, scan_id=scan) is None


def test_stored_set_matches_read_time_derivation(store) -> None:
    scan, tenant = f"equiv-{uuid4().hex[:10]}", f"te-{uuid4().hex[:8]}"
    with tenant_scope(tenant):
        store.save_graph(build_unified_graph_from_report(shared_server_estate(agents=20, group_size=10), scan_id=scan, tenant_id=tenant))
        stored = store.snapshot_attack_paths(tenant_id=tenant, scan_id=scan)
        derived = _derived_attack_paths(store.load_graph(tenant_id=tenant, scan_id=scan))
        subset = store.snapshot_attack_paths(tenant_id=tenant, scan_id=scan, source_ids={derived[0].source})
        store.delete_snapshot(tenant_id=tenant, scan_id=scan)
    assert stored is not None and subset is not None
    assert [path.to_dict() for path in stored.paths] == [path.to_dict() for path in derived]
    assert [path.to_dict() for path in subset.paths] == [path.to_dict() for path in derived if path.source == derived[0].source]


def test_queue_page_reads_stored_order_and_facets(store) -> None:
    from agent_bom.graph.attack_path_queue_rank import rank_attack_paths

    scan, tenant = f"queue-{uuid4().hex[:10]}", f"tq-{uuid4().hex[:8]}"
    with tenant_scope(tenant):
        store.save_graph(build_unified_graph_from_report(shared_server_estate(agents=20, group_size=10), scan_id=scan, tenant_id=tenant))
        loaded = store.load_graph(tenant_id=tenant, scan_id=scan)
        page = store.snapshot_queue_page(tenant_id=tenant, scan_id=scan, offset=2, limit=5, min_severity="critical", has_credential=True)
        store.delete_snapshot(tenant_id=tenant, scan_id=scan)
    expected = rank_attack_paths(_derived_attack_paths(loaded), loaded.nodes, min_severity="critical", has_credential=True)
    assert page is not None and page.total == len(expected)
    assert [path.to_dict() for path in page.paths] == [path.to_dict() for path in expected[2:7]]
