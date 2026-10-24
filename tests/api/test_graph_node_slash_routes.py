"""Node path routes accept canonical ids that contain "/"."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.test_graph_api import _RecordingGraphStore


@pytest.fixture
def recording_graph_store():
    original = api_stores._graph_store
    store = _RecordingGraphStore()
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


@pytest.mark.parametrize(
    "node_id",
    [
        "cloud_resource:aws:aws_instance:111122223333/us-east-1/i-0de00000000000001",
        "misconfig:iac:/workspace/Dockerfile:2",
        "pkg:npm/@scope/tool",
    ],
)
def test_graph_node_path_routes_accept_ids_containing_slashes(recording_graph_store, node_id):
    graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
    graph.add_node(UnifiedNode(id="source", entity_type=EntityType.AGENT, label="source"))
    graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.MISCONFIGURATION, label="finding"))
    graph.add_edge(UnifiedEdge(source="source", target=node_id, relationship=RelationshipType.VULNERABLE_TO, traversable=True))
    recording_graph_store.graph = graph
    client = TestClient(app)

    detail = client.get(f"/v1/graph/node/{node_id}", params={"scan_id": "store-scan"})
    assert detail.status_code == 200, detail.text
    assert detail.json()["node"]["id"] == node_id
    encoded = client.get("/v1/graph/node/" + node_id.replace("/", "%2F"), params={"scan_id": "store-scan"})
    assert encoded.status_code == 200
    assert encoded.json()["node"]["id"] == node_id
    neighbors = client.get(f"/v1/graph/node/{node_id}/neighbors", params={"scan_id": "store-scan"})
    assert neighbors.status_code == 200
    assert neighbors.json()["node_id"] == node_id
    assert neighbors.json()["total_neighbors"] == 1
