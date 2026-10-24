"""Generation pinning and not-found contracts agree across graph, inventory and MCP reads."""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, UnifiedNode
from agent_bom.mcp_errors import CODE_NOT_FOUND_RESOURCE
from agent_bom.mcp_tools.inventory import inventory_list_impl, inventory_summary_impl
from tests.test_graph_tenant_scope_and_bounds import _path_graph


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())
    store = SQLiteGraphStore(tmp_path / "generation.db")
    graph = _path_graph("default")
    for index in range(3):
        graph.add_node(UnifiedNode(id=f"principal:reader-{index}", entity_type=EntityType.SERVICE_ACCOUNT, label=f"reader-{index}"))
    store.save_graph(graph)
    monkeypatch.setattr(api_stores, "_graph_store", store)
    return TestClient(app), store


def _other(generation: str) -> str:
    return ("0" if generation[0] != "0" else "1") + generation[1:]


@pytest.mark.parametrize("path", ["/v1/inventory/assets", "/v1/graph/exposure-paths"])
def test_snapshot_generation_is_honoured_not_ignored(client, path):
    http, _store = client
    first = http.get(path)
    assert first.status_code == 200, first.text
    generation = first.json()["snapshot_generation"]
    assert generation
    assert http.get(path, params={"snapshot_generation": generation}).status_code == 200
    stale = http.get(path, params={"snapshot_generation": _other(generation)})
    assert stale.status_code == 409, stale.text


def test_search_cursor_carries_its_generation_like_graph_and_attack_paths(client):
    http, _store = client
    first = http.get("/v1/graph/search", params={"q": "reader", "limit": 1})
    assert first.status_code == 200, first.text
    body = first.json()
    cursor, generation = body["pagination"]["next_cursor"], body["snapshot_generation"]
    assert cursor and generation
    second = http.get("/v1/graph/search", params={"q": "reader", "limit": 1, "cursor": cursor})
    assert second.status_code == 200, second.text
    assert second.json()["snapshot_generation"] == generation
    assert second.json()["results"][0]["id"] != body["results"][0]["id"]
    pinned = http.get("/v1/graph/search", params={"q": "reader", "limit": 1, "cursor": cursor, "snapshot_generation": generation})
    assert pinned.status_code == 200 and pinned.json()["results"] == second.json()["results"]
    mismatch = http.get("/v1/graph/search", params={"q": "reader", "limit": 1, "cursor": cursor, "snapshot_generation": _other(generation)})
    assert mismatch.status_code == 409, mismatch.text


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", [inventory_summary_impl, inventory_list_impl])
async def test_mcp_inventory_unknown_scan_is_not_found(client, tool):
    _http, store = client
    body = json.loads(await tool(scan_id="nope", _get_graph_store=lambda: store, _truncate_response=lambda v: v))
    assert body["error"]["code"] == CODE_NOT_FOUND_RESOURCE, body
