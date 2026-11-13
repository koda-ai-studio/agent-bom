"""``GET /v1/graph/cluster-map``: tenant scope, accuracy against the inventory, bounds and cost at scale."""

from __future__ import annotations

import json
from collections import Counter

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, graph_cluster_index_cache, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import graph as routes
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.cluster_map import FIRST_FRAME_ELEMENT_BUDGET

pytestmark = pytest.mark.graph_contract("warn")

TENANTS = ("tenant-a", "tenant-b")


def _estate(tenant: str, *, agents: int = 3, scan_id: str = "cluster-scan") -> UnifiedGraph:
    g = UnifiedGraph(tenant_id=tenant, scan_id=scan_id, created_at="2026-11-13T00:00:00Z")
    g.add_node(UnifiedNode(id="provider:aws", entity_type=EntityType.PROVIDER, label=f"{tenant}-aws"))
    g.add_node(UnifiedNode(id="vuln:crit", entity_type=EntityType.VULNERABILITY, label="CVE-crit", severity="critical"))
    for a in range(agents):
        agent = f"agent:{a}"
        g.add_node(UnifiedNode(id=agent, entity_type=EntityType.AGENT, label=f"{tenant}-agent-{a}"))
        g.add_edge(UnifiedEdge(source="provider:aws", target=agent, relationship=RelationshipType.PLATFORM_FOR))
        for s in range(2):
            server = f"server:{a}:{s}"
            g.add_node(UnifiedNode(id=server, entity_type=EntityType.SERVER, label=f"srv-{a}-{s}"))
            g.add_edge(UnifiedEdge(source=agent, target=server, relationship=RelationshipType.USES))
            for p in range(4):
                pkg = f"pkg:{a}:{s}:{p}"
                g.add_node(
                    UnifiedNode(
                        id=pkg,
                        entity_type=EntityType.PACKAGE,
                        label=f"lib-{a}-{s}-{p}",
                        attributes={"ecosystem": "npm" if p % 2 else "pypi"},
                    )
                )
                g.add_edge(UnifiedEdge(source=server, target=pkg, relationship=RelationshipType.DEPENDS_ON))
    g.add_edge(UnifiedEdge(source="pkg:0:0:0", target="vuln:crit", relationship=RelationshipType.VULNERABLE_TO))
    g.attack_paths = [
        AttackPath(
            source="agent:0", target="vuln:crit", hops=["agent:0", "server:0:0", "pkg:0:0:0", "vuln:crit"], edges=[], composite_risk=80.0
        )
    ]
    return g


@pytest.fixture
def api(tmp_path, monkeypatch):
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    graph_cluster_index_cache.clear()
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_estate("tenant-a"))
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    headers = {}
    for tenant in TENANTS:
        token, key = auth.create_api_key(tenant, auth.Role.VIEWER, tenant_id=tenant)
        keys.add(key)
        headers[tenant] = {"Authorization": f"Bearer {token}"}
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    try:
        with TestClient(app) as client:
            yield client, store, headers
    finally:
        graph_cluster_index_cache.clear()
        reset_backpressure_for_tests()


def _get(client, headers, **params):
    return client.get("/v1/graph/cluster-map", params=params, headers=headers)


def test_member_and_edge_counts_reconcile_with_the_inventory_for_the_same_snapshot(api) -> None:
    client, store, headers = api
    body = _get(client, headers["tenant-a"]).json()
    stats = store.snapshot_stats(tenant_id="tenant-a", scan_id="cluster-scan")
    by_type: Counter[str] = Counter()
    for cluster in body["clusters"]:
        by_type.update(cluster["entity_types"])
    assert dict(by_type) == stats["node_types"]
    assert body["summary"]["total_nodes"] == stats["total_nodes"]
    summary = body["summary"]
    drawn = sum(edge["count"] for edge in body["edges"])
    assert (
        drawn + summary["hidden_bundle_edge_count"] + summary["internal_edge_count"] + summary["filtered_edge_count"]
        == stats["total_edges"]
    )
    # One bundled edge per group pair, with the exact count of the edges it stands for.
    packages = {node["id"] for node in body["nodes"] if node.get("cluster_key", "").startswith("package:")}
    server = next(node["id"] for node in body["nodes"] if node.get("cluster_key") == "type:server")
    depends = [edge for edge in body["edges"] if edge["source"] == server and edge["target"] in packages]
    assert sum(edge["count"] for edge in depends) == 24
    assert body["snapshot_generation"]


def test_attack_path_membership_comes_from_the_stored_paths(api) -> None:
    client, store, headers = api
    stored = _estate("tenant-a")
    store.save_graph(stored)
    body = _get(client, headers["tenant-a"]).json()
    agents = next(node for node in body["nodes"] if node.get("cluster_key") == "type:agent")
    assert agents["on_attack_path_count"] == 1
    assert body["clusters"][0]["risky"] is True


def test_tenant_isolation(api) -> None:
    client, store, headers = api
    assert _get(client, headers["tenant-b"]).status_code == 503
    # Naming another tenant's snapshot answers nothing of it.
    other = _get(client, headers["tenant-b"], scan_id="cluster-scan")
    assert other.status_code == 404
    assert "tenant-a" not in other.text
    store.save_graph(_estate("tenant-b", agents=1))
    mine, theirs = _get(client, headers["tenant-a"]).json(), _get(client, headers["tenant-b"]).json()
    assert mine["tenant_id"] == "tenant-a" and theirs["tenant_id"] == "tenant-b"
    assert mine["summary"]["total_nodes"] != theirs["summary"]["total_nodes"]
    assert "tenant-a" not in json.dumps(theirs) and "tenant-b" not in json.dumps(mine)
    focus = _get(client, headers["tenant-b"], focus="agent:2")
    assert focus.json()["focus"]["found"] is False  # agent:2 exists only in tenant-a's estate


def test_expand_page_and_focus_round_trip(api) -> None:
    client, _store, headers = api
    first = _get(client, headers["tenant-a"]).json()
    npm = next(node["id"] for node in first["nodes"] if node.get("cluster_key") == "package:npm")
    opened = _get(client, headers["tenant-a"], expand=[npm], member_limit=4).json()
    more = next(node for node in opened["nodes"] if node["kind"] == "more")
    assert more["count"] == 12 - 4 and more["next_offset"] == 4
    paged = _get(client, headers["tenant-a"], expand=[npm], page=[f"{more['next_offset']}:{npm}"], member_limit=4).json()
    shown = {node["id"] for node in opened["nodes"] if node["kind"] == "member"}
    shown_next = {node["id"] for node in paged["nodes"] if node["kind"] == "member"}
    assert shown and shown_next and not shown & shown_next
    assert _get(client, headers["tenant-a"], page=["x:" + npm]).status_code == 422
    focused = _get(client, headers["tenant-a"], focus="pkg:2:1:3", member_limit=2).json()
    assert any(node["id"] == "pkg:2:1:3" and node["focused"] for node in focused["nodes"])


def test_large_estate_frame_is_bounded_and_the_aggregation_is_built_once(api) -> None:
    client, store, headers = api
    store.save_graph(_estate("tenant-a", agents=600, scan_id="large-scan"))
    first = _get(client, headers["tenant-a"], scan_id="large-scan")
    assert first.status_code == 200
    body = first.json()
    assert body["summary"]["total_nodes"] == 2 + 600 * (1 + 2 + 8)
    assert body["summary"]["element_count"] <= FIRST_FRAME_ELEMENT_BUDGET
    assert len(first.content) < 40_000
    builds = graph_cluster_index_cache.stats()["builds"]
    agents = next(node["id"] for node in body["nodes"] if node.get("cluster_key") == "type:agent")
    for _ in range(5):
        view = _get(client, headers["tenant-a"], scan_id="large-scan", expand=[agents], member_limit=50)
        assert view.status_code == 200
        payload = view.json()
        # The work of a frame is the edges of the members it draws, never the estate's 13k edges.
        assert payload["cost"]["edges_scanned"] == 50 * 3
        assert len(view.content) < 120_000
    assert graph_cluster_index_cache.stats()["builds"] == builds


def test_snapshot_commit_warm_up_builds_the_aggregation_before_the_first_reader(api) -> None:
    from agent_bom.api.graph_rollup_prewarm import prewarm_rollup

    client, store, headers = api
    graph_cluster_index_cache.clear()
    prewarm_rollup(store, tenant_id="tenant-a")
    assert graph_cluster_index_cache.stats()["builds"] == 1
    assert _get(client, headers["tenant-a"]).status_code == 200
    assert graph_cluster_index_cache.stats()["builds"] == 1
