"""A bounded ``/v1/graph/query`` never reports its page as the source total.

The investigation canvas loads a scope with a small ``max_nodes`` and widens it
on "Show more". The traversal graph only ever holds what was returned, so its
``stats.total_nodes_source`` equalled the page size (4 of an org's 42 direct
children read as "4 in the source"). A bounded walk cannot know its total; it
must say so, while an unbounded walk still reports the exact total.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

CHILDREN = 42


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    graph = UnifiedGraph(scan_id="query-total", tenant_id="default")
    graph.add_node(UnifiedNode(id="org:o", entity_type=EntityType.ORG, label="o"))
    for index in range(CHILDREN):
        account = f"account:{index:02d}"
        graph.add_node(UnifiedNode(id=account, entity_type=EntityType.ACCOUNT, label=account))
        graph.add_edge(UnifiedEdge(source="org:o", target=account, relationship=RelationshipType.CONTAINS))
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(graph)
    set_graph_store(store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(None)  # type: ignore[arg-type]


def _query(client: TestClient, max_nodes: int) -> dict:
    response = client.post(
        "/v1/graph/query",
        json={"roots": ["org:o"], "scan_id": "query-total", "max_depth": 1, "max_nodes": max_nodes, "include_roots": True},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_bounded_query_does_not_certify_its_page_as_the_source_total(client: TestClient) -> None:
    body = _query(client, 4)
    assert body["truncated"] is True
    assert body["stats"]["total_nodes"] == 4
    assert body["stats"]["total_nodes_source"] is None
    assert body["completeness"].get("total") is None


def test_complete_query_reports_exact_source_total(client: TestClient) -> None:
    body = _query(client, 200)
    assert body["truncated"] is False
    assert body["stats"]["total_nodes"] == CHILDREN + 1
    assert body["stats"]["total_nodes_source"] == CHILDREN + 1
