"""Every graph node names its semantic layer, and exposure reaches the node payload the UI reads."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, GraphSemanticLayer, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.legend import ENTITY_LEGEND
from agent_bom.graph.node import NodeDimensions
from agent_bom.graph.semantic_layer import LAYER_BY_ENTITY_TYPE, SEMANTIC_LAYER_COLUMNS, node_payload, semantic_layer
from tests.test_graph_api import _RecordingGraphStore

_LAYERS = {layer.value for layer in GraphSemanticLayer}


def test_every_entity_type_maps_to_one_layer() -> None:
    assert set(LAYER_BY_ENTITY_TYPE) == {entity.value for entity in EntityType}
    assert set(LAYER_BY_ENTITY_TYPE.values()) <= _LAYERS
    # The schema legend and the node payload agree per kind.
    assert {entry.key: entry.layer for entry in ENTITY_LEGEND} == LAYER_BY_ENTITY_TYPE


def test_recorded_layer_wins_then_surface_then_kind() -> None:
    gateway = UnifiedNode(id="r", entity_type=EntityType.CLOUD_RESOURCE, label="r", attributes={"semantic_layer": "api_gateway"})
    assert semantic_layer(gateway) == "api_gateway"
    ci = UnifiedNode(id="t", entity_type=EntityType.TOOL, label="t", dimensions=NodeDimensions(surface="ci"))
    assert semantic_layer(ci) == "ci"
    # A surface that is not a layer name (``container-image``) never overrides the kind.
    image = UnifiedNode(id="i", entity_type=EntityType.CONTAINER, label="i", dimensions=NodeDimensions(surface="container-image"))
    assert semantic_layer(image) == "infra"
    bogus = UnifiedNode(id="b", entity_type=EntityType.PACKAGE, label="b", attributes={"semantic_layer": "nonsense"})
    assert semantic_layer(bogus) == "package"
    assert node_payload(image)["semantic_layer"] == "infra"


@pytest.fixture
def recording_graph_store():
    original = api_stores._graph_store
    store = _RecordingGraphStore()
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s", attributes={"internet_exposed": True}))
    graph.add_node(UnifiedNode(id="pkg:p", entity_type=EntityType.PACKAGE, label="p"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, evidence={"source": "scan"}))
    graph.add_edge(UnifiedEdge(source="server:s", target="pkg:p", relationship=RelationshipType.DEPENDS_ON, evidence={"source": "scan"}))
    return graph


@pytest.mark.parametrize("view", ["full", "summary", "canvas"])
def test_graph_payload_nodes_carry_layer_and_exposure(recording_graph_store, view, monkeypatch) -> None:
    from agent_bom.cloud import runtime_workload_evidence_store as runtime_evidence

    monkeypatch.setattr(runtime_evidence, "_default_store", None)
    recording_graph_store.graph = _graph()
    response = TestClient(app).get("/v1/graph", params={"scan": "store-scan", "view": view})

    assert response.status_code == 200, response.text
    nodes = {node["id"]: node for node in response.json()["nodes"]}
    assert {node_id: node["semantic_layer"] for node_id, node in nodes.items()} == {
        "agent:a": "orchestration",
        "server:s": "mcp_server",
        "pkg:p": "package",
    }
    assert nodes["server:s"]["attributes"]["internet_exposed"] is True


def test_node_detail_carries_layer(recording_graph_store) -> None:
    recording_graph_store.graph = _graph()
    response = TestClient(app).get("/v1/graph/node/server:s", params={"scan": "store-scan"})
    assert response.status_code == 200, response.text
    assert response.json()["node"]["semantic_layer"] == "mcp_server"


def test_summary_exposure_folds_in_the_risk_context_verdict() -> None:
    from agent_bom.api.routes.graph_routes.lean_view import _lean_node

    raw_flag = {"id": "r", "attributes": {"publicly_accessible": True, "risk_context": {"internet_exposed": True}}}
    assert _lean_node(raw_flag)["attributes"] == {"internet_exposed": True}
    private = {"id": "r", "attributes": {"internet_exposed": False}}
    assert _lean_node(private)["attributes"] == {"internet_exposed": False}
    unknown = {"id": "r", "attributes": {"risk_context": {"internet_exposed": None}}}
    assert _lean_node(unknown)["attributes"] == {}


def test_estate_containers_take_the_scope_layer_and_the_first_column() -> None:
    for kind in ("org", "account", "provider", "environment", "fleet"):
        assert LAYER_BY_ENTITY_TYPE[kind] == "scope", kind
    assert set(SEMANTIC_LAYER_COLUMNS) == {layer.value for layer in GraphSemanticLayer}
    column = SEMANTIC_LAYER_COLUMNS
    # Scope contains everything, then entry, workload, agent, MCP server, its reach, then data and findings.
    order = ["scope", "user", "api_gateway", "infra", "orchestration", "mcp_server", "tool", "asset"]
    assert [column[layer] for layer in order] == sorted(column[layer] for layer in order)
    assert len({column[layer] for layer in order}) == len(order)
    assert column["identity"] == column["tool"] and column["finding"] == column["package"] == column["asset"]


def test_schema_publishes_each_layer_column() -> None:
    layers = TestClient(app).get("/v1/graph/schema").json()["semantic_layers"]
    assert {layer["key"]: layer["column"] for layer in layers} == SEMANTIC_LAYER_COLUMNS
