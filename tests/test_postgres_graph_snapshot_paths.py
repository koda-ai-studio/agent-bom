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


def _parity_graph(tenant: str, scan: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan, tenant_id=tenant, created_at="2026-10-12T00:00:00Z")
    for node_id, kind in (
        ("server:z", EntityType.SERVER),
        ("agent:a", EntityType.AGENT),
        ("vuln:CVE-1", EntityType.VULNERABILITY),
        ("server:b", EntityType.SERVER),
        ("vuln:CVE-0", EntityType.VULNERABILITY),
    ):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id, severity="high"))
    for source, target, rel in (
        ("server:z", "vuln:CVE-1", RelationshipType.VULNERABLE_TO),
        ("agent:a", "server:z", RelationshipType.USES),
        ("server:b", "vuln:CVE-0", RelationshipType.VULNERABLE_TO),
        ("agent:a", "server:b", RelationshipType.USES),
    ):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))
    # Emitted out of rank order, with two distinct routes sharing endpoints.
    for hops, edges, risk, finding in (
        (["server:b", "vuln:CVE-0"], ["vulnerable_to"], 10.0, "F0"),
        (["agent:a", "server:z", "vuln:CVE-1"], ["uses", "vulnerable_to"], 90.0, "F1"),
        (["agent:a", "vuln:CVE-1"], ["vulnerable_to"], 90.0, "F2"),
    ):
        graph.attack_paths.append(
            AttackPath(source=hops[0], target=hops[-1], hops=hops, edges=edges, composite_risk=risk, finding_ids=[finding])
        )
    return graph


def test_load_order_and_finding_ids_match_across_backends(store) -> None:
    from agent_bom.graph.snapshot_paths import path_identity

    scan, tenant = f"parity-{uuid4().hex[:10]}", f"tp-{uuid4().hex[:8]}"
    written = _parity_graph(tenant, scan)
    with tenant_scope(tenant):
        store.save_graph(written)
        loaded = store.load_graph(tenant_id=tenant, scan_id=scan)
        _, _, page, total = store.attack_paths(tenant_id=tenant, scan_id=scan)
        store.delete_snapshot(tenant_id=tenant, scan_id=scan)

    expected = sorted(written.attack_paths, key=lambda path: (-path.composite_risk, path_identity(path)))
    assert [(path.hops, path.finding_ids) for path in loaded.attack_paths] == [(path.hops, path.finding_ids) for path in expected]
    assert [path.hops for path in page] == [path.hops for path in expected] and total == 3
    assert list(loaded.nodes) == sorted(written.nodes)
    assert [(edge.source, edge.target) for edge in loaded.edges] == sorted((edge.source, edge.target) for edge in written.edges)


def test_node_with_large_incompressible_attributes_persists(store) -> None:
    import secrets

    scan, tenant = f"wide-{uuid4().hex[:10]}", f"tw-{uuid4().hex[:8]}"
    graph = UnifiedGraph(scan_id=scan, tenant_id=tenant)
    # A brokered database scan records per-table evidence; random tokens defeat
    # compression the way real hashes and identifiers do.
    evidence = {f"table_{i}": secrets.token_hex(32) for i in range(160)}
    graph.add_node(UnifiedNode(id="db:prod", entity_type=EntityType.DATA_STORE, label="prod", attributes={"tables": evidence}))
    with tenant_scope(tenant):
        store.save_graph(graph)
        loaded = store.load_graph(tenant_id=tenant, scan_id=scan)
        store.delete_snapshot(tenant_id=tenant, scan_id=scan)
    assert loaded.nodes["db:prod"].attributes["tables"] == evidence


def test_path_summary_counts_the_queue_index_per_tenant(store) -> None:
    scan = f"summary-{uuid4().hex[:10]}"
    tenant_a, tenant_b = f"sa-{uuid4().hex[:8]}", f"sb-{uuid4().hex[:8]}"
    with tenant_scope(tenant_a):
        store.save_graph(build_unified_graph_from_report(shared_server_estate(agents=20, group_size=10), scan_id=scan, tenant_id=tenant_a))
        summary = store.snapshot_path_summary(tenant_id=tenant_a, scan_id=scan)
        latest = store.snapshot_path_summary(tenant_id=tenant_a)
        queue = store.snapshot_queue_page(tenant_id=tenant_a, scan_id=scan, limit=1)
        stored = store.snapshot_attack_paths(tenant_id=tenant_a, scan_id=scan)
    with tenant_scope(tenant_b):
        foreign = store.snapshot_path_summary(tenant_id=tenant_b, scan_id=scan)
    with tenant_scope(tenant_a):
        store.delete_snapshot(tenant_id=tenant_a, scan_id=scan)
        purged = store.snapshot_path_summary(tenant_id=tenant_a, scan_id=scan)
    assert queue is not None and stored is not None and queue.snapshot_total > 0
    assert summary == latest == (queue.snapshot_total, max(path.composite_risk for path in stored.paths))
    assert foreign is None
    assert purged is None
