"""Both graph store backends derive the same server and agent roles from stored rows.

Inventory's ``role`` facet and the grouped map's lean rows must agree with
:func:`agent_bom.graph.node_roles.node_role` on SQLite and Postgres, stay
tenant-scoped, and honour the inventory filters.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from uuid import uuid4

import pytest

from agent_bom.graph import EntityType, NodeDimensions, UnifiedGraph, UnifiedNode
from agent_bom.graph.cluster_index import ClusterIndex
from agent_bom.graph.cluster_map import cluster_map_view

pytestmark = pytest.mark.graph_contract("warn")

_ASSETS = {"agent", "server", "package"}


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    if request.param == "sqlite":
        yield SQLiteGraphStore(tmp_path / "graph.db")
        return
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL is required for live Postgres role reads")
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


def _node(node_id: str, kind: EntityType, environment: str = "prod", **dims: str) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=kind, label=node_id, dimensions=NodeDimensions(environment=environment, **dims))


def _graph(tenant: str, scan: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan, tenant_id=tenant)
    for node in (
        _node("agent:a", EntityType.AGENT, agent_type="claude-code"),
        _node("agent:b", EntityType.AGENT, environment="dev", agent_type="custom"),
        _node("agent:fw", EntityType.AGENT, agent_type="framework-agent", surface="langchain"),
        _node("server:mcp", EntityType.SERVER, surface="mcp-server"),
        _node("server:legacy", EntityType.SERVER),
        _node("server:runtime", EntityType.SERVER, surface="other"),
        _node("server:runtime-dev", EntityType.SERVER, environment="dev", surface="other"),
        _node("pkg:x", EntityType.PACKAGE, ecosystem="pypi"),
    ):
        graph.add_node(node)
    return graph


def test_role_facet_and_cluster_rows_agree_on_every_backend(store) -> None:
    tenant, other, scan = f"t-{uuid4().hex[:8]}", f"u-{uuid4().hex[:8]}", f"s-{uuid4().hex[:8]}"
    graph = _graph(tenant, scan)
    with tenant_scope(tenant):
        store.save_graph(graph)
        full = store.query_inventory(tenant_id=tenant, scan_id=scan, asset_entity_types=_ASSETS)
        prod = store.query_inventory(tenant_id=tenant, scan_id=scan, asset_entity_types=_ASSETS, environment="prod")
        nodes, edges, hops, pairs = store.load_cluster_rows(tenant_id=tenant, scan_id=scan)

    assert sorted(full["facets"]["role"], key=lambda b: b["value"]) == [
        {"value": "agent", "count": 2},
        {"value": "framework_agent", "count": 1},
        {"value": "mcp_server", "count": 2},
        {"value": "other_server", "count": 2},
    ]
    assert sorted(prod["facets"]["role"], key=lambda b: b["value"]) == [
        {"value": "agent", "count": 1},
        {"value": "framework_agent", "count": 1},
        {"value": "mcp_server", "count": 2},
        {"value": "other_server", "count": 1},
    ]
    # Type buckets still count every stored node of the type.
    assert {b["value"]: b["count"] for b in full["facets"]["type"]} == {"agent": 3, "server": 4, "package": 1}

    expected_nodes, _expected_edges, _hops, _pairs = ClusterIndex.rows_from_graph(graph)
    assert sorted(nodes) == sorted(expected_nodes)
    roles = {row[0]: row[7] for row in nodes}
    assert roles["server:legacy"] == "mcp_server" and roles["server:runtime"] == "other_server"
    assert roles["agent:fw"] == "framework_agent" and roles["pkg:x"] == ""
    groups = {c["cluster_key"]: c["member_count"] for c in cluster_map_view(ClusterIndex.from_rows(nodes, edges, hops, pairs))["clusters"]}
    assert groups["type:agent"] == 2 and groups["agent:framework"] == 1
    assert groups["type:server"] == 2 and groups["server:other"] == 2

    with tenant_scope(other):
        assert store.query_inventory(tenant_id=other, scan_id=scan, asset_entity_types=_ASSETS)["facets"]["role"] == []
