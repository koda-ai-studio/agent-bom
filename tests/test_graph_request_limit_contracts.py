"""Request limits say what was applied: one truth between OpenAPI and the response.

* ``/v1/graph/query`` rejected ``max_depth=6`` with a 422 (the deployment
  budget is 5) while OpenAPI advertised a maximum of 10. A request within the
  published ceiling is now clamped to the budget and the clamp is disclosed.
* ``/v1/graph/exposure-paths?limit=100`` silently returned 25 paths while
  ``pagination.limit`` echoed 100: the MCP transport budget was applied to
  REST. REST honours ``limit`` (documented max 100); MCP still fits its
  transport and echoes the limit it actually applied.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_mcp_graph_agent_parity import _api_env, _Estate, demo, demo_dir  # noqa: F401

pytestmark = pytest.mark.graph_contract("warn")


def _chain(length: int) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="chain-scan", tenant_id="default", created_at="2026-10-18T00:00:00+00:00")
    ids = [f"agent:{index}" for index in range(length)]
    for node_id in ids:
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.AGENT, label=node_id))
    for source, target in zip(ids, ids[1:]):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.DELEGATED_TO))
    return graph


@pytest.fixture
def chain_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    for key in ("MAX_DEPTH", "MAX_NODES", "MAX_EDGES", "TIMEOUT_MS"):
        monkeypatch.delenv(f"AGENT_BOM_GRAPH_QUERY_{key}", raising=False)
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(_chain(9))
    set_graph_store(store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(None)  # type: ignore[arg-type]


def test_query_depth_within_the_published_ceiling_is_clamped_and_disclosed(chain_client) -> None:
    response = chain_client.post("/v1/graph/query", json={"roots": ["agent:0"], "max_depth": 6})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["max_depth"] == 5
    assert body["budget"]["max_depth"] == 5
    assert body["budget_applied"] == {"max_depth": {"requested": 6, "applied": 5}}
    assert max(body["depth_by_node"].values()) == 5
    assert body["completeness"]["reason"] == "depth_limit"


def test_query_within_budget_reports_no_clamp(chain_client) -> None:
    body = chain_client.post("/v1/graph/query", json={"roots": ["agent:0"], "max_depth": 3}).json()

    assert body["max_depth"] == 3
    assert body["budget_applied"] == {}


def test_query_past_the_published_ceiling_is_still_rejected(chain_client) -> None:
    assert chain_client.post("/v1/graph/query", json={"roots": ["agent:0"], "max_depth": 11}).status_code == 422


def test_openapi_states_the_ceiling_and_the_budget_clamp() -> None:
    schema = app.openapi()["components"]["schemas"]["GraphQueryRequest"]["properties"]["max_depth"]

    assert schema["maximum"] == 10
    assert "AGENT_BOM_GRAPH_QUERY_MAX_DEPTH" in schema["description"]
    assert "budget_applied" in schema["description"]


def test_rest_exposure_paths_honour_limit_beyond_the_mcp_transport_budget(demo: _Estate, monkeypatch) -> None:  # noqa: F811
    from agent_bom.mcp_tools import exposure_queue

    total = demo.rest("/v1/graph/exposure-paths", limit=100)["total"]
    assert total >= 4
    # A transport budget no full path fits: REST must not apply it at all.
    monkeypatch.setattr(exposure_queue, "MCP_MAX_RESPONSE_CHARS", 1_000)
    rest = demo.rest("/v1/graph/exposure-paths", limit=100)

    assert rest["count"] == len(rest["paths"]) == min(total, 100)
    assert rest["pagination"]["limit"] == 100


def test_mcp_exposure_paths_echo_the_limit_they_applied(demo: _Estate, monkeypatch) -> None:  # noqa: F811
    from agent_bom.mcp_tools import exposure_queue
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    # A transport budget that fits two full paths and not three.
    budget = len(demo.mcp_raw(exposure_paths_impl, limit=2, view="full")) + 200
    monkeypatch.setattr(exposure_queue, "MCP_MAX_RESPONSE_CHARS", budget)
    raw = demo.mcp_raw(exposure_paths_impl, limit=100, view="full")
    payload: dict[str, Any] = json.loads(raw)

    pagination = payload["pagination"]
    assert 1 <= pagination["returned"] < payload["total"]
    assert pagination["limit"] == pagination["returned"]
    assert pagination["requested_limit"] == 100
    assert pagination["limit_reason"] == "response_budget"
    assert pagination["has_more"] is True and pagination["next_cursor"]
    assert len(raw) <= budget


def test_mcp_exposure_paths_within_budget_echo_the_requested_limit(demo: _Estate) -> None:  # noqa: F811
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    pagination = demo.mcp(exposure_paths_impl, limit=3)["pagination"]

    assert pagination["limit"] == 3
    assert "requested_limit" not in pagination
