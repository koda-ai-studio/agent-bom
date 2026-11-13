"""Node risk context reaches the API and MCP unchanged, per tenant."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.risk_context_overlay import apply_node_risk_context

SCAN = "risk-scan"


def _graph(tenant_id: str, *, exposed: bool) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=SCAN, tenant_id=tenant_id)
    graph.add_node(
        UnifiedNode(
            id="vm:web", entity_type=EntityType.CLOUD_RESOURCE, label="web", attributes={"internet_exposed": exposed}, data_sources=["aws"]
        )
    )
    graph.add_node(UnifiedNode(id="role:app", entity_type=EntityType.ROLE, label="app", attributes={"admin_equivalence_status": "admin"}))
    graph.add_node(UnifiedNode(id="ds:claims", entity_type=EntityType.DATA_STORE, label="claims", attributes={"data_sensitivity": "phi"}))
    graph.add_edge(UnifiedEdge(source="vm:web", target="role:app", relationship=RelationshipType.ASSUMES, traversable=True))
    graph.add_edge(UnifiedEdge(source="role:app", target="ds:claims", relationship=RelationshipType.CAN_ACCESS, traversable=True))
    graph.attack_paths = [
        AttackPath(
            source="vm:web",
            target="ds:claims",
            hops=["vm:web", "role:app", "ds:claims"],
            edges=["assumes", "can_access"],
            composite_risk=70.0,
        )
    ]
    apply_node_risk_context(graph)
    return graph


@pytest.fixture()
def store(tmp_path: Any, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())
    graph_store = SQLiteGraphStore(tmp_path / "risk-graph.db")
    graph_store.save_graph(_graph("default", exposed=True))
    graph_store.save_graph(_graph("tenant-b", exposed=False))
    original = api_stores._graph_store
    set_graph_store(graph_store)
    try:
        yield graph_store
    finally:
        api_stores._graph_store = original
        reset_backpressure_for_tests()


def test_node_detail_serves_the_stored_context(store: SQLiteGraphStore) -> None:
    body = TestClient(app).get("/v1/graph/node/vm:web", params={"scan_id": SCAN}).json()
    context = body["node"]["attributes"]["risk_context"]
    assert context["internet_exposed"] is True
    assert context["scan_id"] == SCAN
    assert context["reasons"][0]["rule"] == "recorded_internet_exposed"
    jewel = TestClient(app).get("/v1/graph/node/ds:claims", params={"scan_id": SCAN}).json()["node"]["attributes"]["risk_context"]
    assert jewel["crown_jewel"] is True


def test_each_tenant_reads_only_its_own_context(store: SQLiteGraphStore) -> None:
    own = store.nodes_by_ids(scan_id=SCAN, tenant_id="default", node_ids={"vm:web"})
    other = store.nodes_by_ids(scan_id=SCAN, tenant_id="tenant-b", node_ids={"vm:web"})
    assert own[0].attributes["risk_context"]["internet_exposed"] is True
    assert other[0].attributes["risk_context"]["internet_exposed"] is False
    served = TestClient(app).get("/v1/graph/node/vm:web", params={"scan_id": SCAN}).json()
    assert served["node"]["attributes"]["risk_context"]["internet_exposed"] is True


def test_mcp_exposure_paths_carry_the_same_context(store: SQLiteGraphStore) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    def call(view: str) -> dict[str, Any]:
        payload = json.loads(asyncio.run(exposure_paths_impl(scan_id=SCAN, limit=10, view=view, _get_graph_store=lambda: store)))
        assert "error" not in payload, payload
        return payload["paths"][0]

    full = call("full")
    refs = {ref["id"]: ref for ref in full["hops"]}
    api_node = TestClient(app).get("/v1/graph/node/ds:claims", params={"scan_id": SCAN}).json()["node"]
    assert refs["ds:claims"]["riskContext"] == api_node["attributes"]["risk_context"]
    assert refs["vm:web"]["riskContext"]["internet_exposed"] is True

    summary = call("summary")
    assert summary["source"]["risk"]["internet_exposed"] is True
    assert summary["target"]["risk"] == {
        "internet_exposed": None,
        "privilege_level": None,
        "is_admin": None,
        "data_sensitivity": "phi",
        "crown_jewel": True,
    }
