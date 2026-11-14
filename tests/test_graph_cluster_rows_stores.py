"""The grouped map's lean snapshot read is the same on SQLite and Postgres, and tenant-scoped."""

from __future__ import annotations

import os
from contextlib import contextmanager
from uuid import uuid4

import pytest

from agent_bom.graph.cluster_index import TOP_PATHS_FOR_BUNDLES, ClusterIndex, hop_pairs
from agent_bom.graph.cluster_map import cluster_map_view
from tests.test_graph_cluster_map import estate

pytestmark = pytest.mark.graph_contract("warn")


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    if request.param == "sqlite":
        yield SQLiteGraphStore(tmp_path / "graph.db")
        return
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL is required for live Postgres grouped-map reads")
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


def _graph(tenant: str, scan: str):
    graph = estate()
    graph.tenant_id, graph.scan_id = tenant, scan
    return graph


def test_store_rows_build_the_same_map_as_the_graph_and_stay_in_their_tenant(store) -> None:
    tenant, other, scan = f"t-{uuid4().hex[:8]}", f"u-{uuid4().hex[:8]}", f"s-{uuid4().hex[:8]}"
    graph = _graph(tenant, scan)
    with tenant_scope(tenant):
        store.save_graph(graph)
        nodes, edges, hops, pairs = store.load_cluster_rows(tenant_id=tenant, scan_id=scan)
        stored = store.snapshot_attack_paths(tenant_id=tenant, scan_id=scan)
    expected_nodes, expected_edges, _legacy_hops, _legacy_pairs = ClusterIndex.rows_from_graph(graph)
    assert sorted(nodes) == sorted(expected_nodes)
    assert sorted(edges) == sorted(expected_edges)
    # Membership is the stored path index the attack-path queue serves, not the graph's in-memory paths.
    assert stored is not None and stored.paths
    expected_hops = {hop for path in stored.paths for hop in path.hops}
    expected_pairs = hop_pairs([list(path.hops) for path in stored.paths][:TOP_PATHS_FOR_BUNDLES])
    assert hops == expected_hops and _legacy_hops < hops
    assert pairs == expected_pairs and ("agent:a", "server:s1") in pairs
    from_store = cluster_map_view(ClusterIndex.from_rows(sorted(nodes), sorted(edges), hops, pairs))
    from_graph = cluster_map_view(ClusterIndex.from_rows(sorted(expected_nodes), sorted(expected_edges), expected_hops, expected_pairs))
    assert from_store == from_graph
    with tenant_scope(other):
        assert store.load_cluster_rows(tenant_id=other, scan_id=scan) == ([], [], set(), set())
