"""``GET /v1/graph`` node pages: bounded, marked context; every node ranked exactly once per walk."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests._demo_estate_fixtures import demo_estate_client, demo_graph_get  # noqa: F401
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_CHAINS = 700


def _chain_graph() -> UnifiedGraph:
    """Each ranked resource sits under its own group, under its own account: two ancestors per resource."""
    graph = UnifiedGraph(tenant_id="tenant-a", scan_id="estate")
    for index in range(_CHAINS):
        res, grp, acct = f"res:{index:04}", f"grp:{index:04}", f"acct:{index:04}"
        graph.add_node(UnifiedNode(id=res, entity_type=EntityType.CLOUD_RESOURCE, label=res, risk_score=10))
        graph.add_node(UnifiedNode(id=grp, entity_type=EntityType.CLOUD_RESOURCE, label=grp, risk_score=0))
        graph.add_node(UnifiedNode(id=acct, entity_type=EntityType.ACCOUNT, label=acct, risk_score=0))
        graph.add_edge(UnifiedEdge(source=grp, target=res, relationship=RelationshipType.CONTAINS))
        graph.add_edge(UnifiedEdge(source=acct, target=grp, relationship=RelationshipType.CONTAINS))
    return graph


@pytest.fixture
def client(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_chain_graph())
    enable_trusted_proxy_env()
    set_graph_store(store)
    try:
        with TestClient(app, headers=proxy_headers(tenant="tenant-a")) as test_client:
            yield test_client
    finally:
        set_graph_store(None)
        disable_trusted_proxy_env()


def assert_bounded_marked_page(body: dict, limit: int) -> list[str]:
    """Check one page's bound and context marking; return its ranked node ids."""
    scope = body["completeness"]
    ranked, context, endpoints = scope["ranked"], scope["context_nodes"], scope["endpoint_nodes"]
    assert scope["context_limit"] == max(limit, 500)
    assert ranked <= limit
    assert context <= scope["context_limit"]
    assert endpoints <= len(body["edges"])
    assert scope["edge_returned"] <= scope["edge_limit"]
    assert len(body["nodes"]) == ranked + context + endpoints == scope["returned"]
    assert all("context" not in node for node in body["nodes"][:ranked])
    assert all(node.get("context") is True for node in body["nodes"][ranked:])
    ids = {node["id"] for node in body["nodes"]}
    assert all(edge["source"] in ids and edge["target"] in ids for edge in body["edges"])
    return [node["id"] for node in body["nodes"][:ranked]]


def test_context_is_capped_nearest_parent_first_and_discloses_the_cut(client):
    body = client.get("/v1/graph", params={"scan_id": "estate", "limit": _CHAINS}).json()
    ranked = assert_bounded_marked_page(body, _CHAINS)
    assert len(ranked) == _CHAINS and all(node_id.startswith("res:") for node_id in ranked)
    scope = body["completeness"]
    assert scope["context_nodes"] == _CHAINS
    assert scope["context_omitted"] == _CHAINS
    assert scope["context_truncated"] is True
    context_ids = {node["id"] for node in body["nodes"][_CHAINS:]}
    # The direct parents survive the cut; the farther accounts are the ones omitted.
    assert context_ids == {f"grp:{index:04}" for index in range(_CHAINS)}


def test_small_page_keeps_its_whole_containment_spine(client):
    body = client.get("/v1/graph", params={"scan_id": "estate", "limit": 50}).json()
    assert_bounded_marked_page(body, 50)
    scope = body["completeness"]
    assert scope["context_nodes"] == 100
    assert scope["context_omitted"] == 0 and scope["context_truncated"] is False


@pytest.mark.parametrize("limit", [97, 333, _CHAINS])
def test_full_cursor_walk_ranks_every_node_exactly_once(client, limit):
    params: dict = {"scan_id": "estate", "limit": limit}
    ranked: list[str] = []
    for _ in range(3 * _CHAINS + 1):
        body = client.get("/v1/graph", params=params).json()
        ranked += assert_bounded_marked_page(body, limit)
        if not body["pagination"]["has_more"]:
            break
        params = {"limit": limit, "cursor": body["pagination"]["next_cursor"]}
    assert len(ranked) == len(set(ranked)) == 3 * _CHAINS


def test_demo_estate_walk_is_bounded_and_ranks_every_node_once(demo_estate_client):  # noqa: F811
    params: dict = {"limit": 1000}
    ranked: list[str] = []
    total = None
    for _ in range(20):
        body = demo_graph_get(demo_estate_client, "/v1/graph", params).json()
        ranked += assert_bounded_marked_page(body, 1000)
        assert len(body["nodes"]) <= 1000 + body["completeness"]["context_limit"] + len(body["edges"])
        total = body["pagination"]["total"]
        if not body["pagination"]["has_more"]:
            break
        params = {"limit": 1000, "cursor": body["pagination"]["next_cursor"]}
    assert total and len(ranked) == len(set(ranked)) == total
