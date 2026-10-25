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
        graph.add_node(UnifiedNode(id=f"agent:reader-{index}", entity_type=EntityType.AGENT, label=f"agent-reader-{index}"))
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


@pytest.mark.parametrize("params", [{}, {"q": "reader"}], ids=["page", "search"])
def test_agents_cursor_carries_its_generation_like_graph_and_search(client, params):
    http, _store = client
    first = http.get("/v1/graph/agents", params=params | {"limit": 1})
    assert first.status_code == 200, first.text
    body = first.json()
    cursor, generation = body["pagination"]["next_cursor"], body["snapshot_generation"]
    assert cursor and generation
    second = http.get("/v1/graph/agents", params=params | {"limit": 1, "cursor": cursor})
    assert second.status_code == 200, second.text
    assert second.json()["snapshot_generation"] == generation
    assert second.json()["agents"][0]["id"] != body["agents"][0]["id"]
    pinned = http.get("/v1/graph/agents", params=params | {"limit": 1, "cursor": cursor, "snapshot_generation": generation})
    assert pinned.status_code == 200 and pinned.json()["agents"] == second.json()["agents"]
    mismatch = http.get("/v1/graph/agents", params=params | {"limit": 1, "cursor": cursor, "snapshot_generation": _other(generation)})
    assert mismatch.status_code == 409, mismatch.text


@pytest.mark.parametrize(
    ("path", "params"),
    [("/v1/graph/incident-edges", {"node_id": "principal:reader"}), ("/v1/inventory/assets/principal:reader", {})],
)
def test_generation_mismatch_is_a_conflict_not_a_validation_error(client, path, params):
    http, _store = client
    generation = http.get("/v1/inventory/assets").json()["snapshot_generation"]
    assert http.get(path, params=params | {"snapshot_generation": generation}).status_code == 200
    stale = http.get(path, params=params | {"snapshot_generation": _other(generation)})
    assert stale.status_code == 409, stale.text


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", [inventory_summary_impl, inventory_list_impl])
async def test_mcp_inventory_unknown_scan_is_not_found(client, tool):
    _http, store = client
    body = json.loads(await tool(scan_id="nope", _get_graph_store=lambda: store, _truncate_response=lambda v: v))
    assert body["error"]["code"] == CODE_NOT_FOUND_RESOURCE, body


def _rotate(store: SQLiteGraphStore) -> None:
    graph = _path_graph("default")
    graph.scan_id = "rotated-scan"
    graph.created_at = "2026-09-26T00:00:00Z"
    for index in range(4):
        graph.add_node(UnifiedNode(id=f"principal:rotated-{index}", entity_type=EntityType.SERVICE_ACCOUNT, label=f"rotated-{index}"))
    store.save_graph(graph)


def test_inventory_cursor_carries_its_generation_and_refuses_a_rotated_snapshot(client):
    http, store = client
    first = http.get("/v1/inventory/assets", params={"limit": 1})
    assert first.status_code == 200, first.text
    body = first.json()
    cursor, generation = body["pagination"]["next_cursor"], body["snapshot_generation"]
    assert cursor and generation
    second = http.get("/v1/inventory/assets", params={"limit": 1, "cursor": cursor})
    assert second.status_code == 200, second.text
    assert second.json()["snapshot_generation"] == generation
    assert second.json()["assets"][0]["id"] != body["assets"][0]["id"]
    pinned = http.get("/v1/inventory/assets", params={"limit": 1, "cursor": cursor, "snapshot_generation": generation})
    assert pinned.status_code == 200 and pinned.json()["assets"] == second.json()["assets"]
    mismatch = http.get("/v1/inventory/assets", params={"limit": 1, "cursor": cursor, "snapshot_generation": _other(generation)})
    assert mismatch.status_code == 409, mismatch.text

    _rotate(store)
    assert http.get("/v1/inventory/assets", params={"limit": 1}).json()["snapshot_generation"] != generation
    stale = http.get("/v1/inventory/assets", params={"limit": 1, "cursor": cursor})
    assert stale.status_code == 409, stale.text


@pytest.mark.asyncio
async def test_mcp_inventory_list_cursor_refuses_a_rotated_snapshot(client):
    _http, store = client

    async def page(**kwargs) -> dict:
        return json.loads(await inventory_list_impl(limit=1, _get_graph_store=lambda: store, _truncate_response=lambda v: v, **kwargs))

    first = await page()
    cursor = first["pagination"]["next_cursor"]
    assert cursor and first["snapshot_generation"]
    second = await page(cursor=cursor)
    assert "error" not in second, second
    assert second["assets"][0]["id"] != first["assets"][0]["id"]

    _rotate(store)
    stale = await page(cursor=cursor)
    assert stale["error"]["details"]["http_status"] == 409, stale
    malformed = await page(cursor="g1.NQ")
    assert malformed["error"]["details"]["http_status"] == 422, malformed
