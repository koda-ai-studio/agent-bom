"""A snapshot with no durable generation still gets a correct roll-up cache key.

Without a generation the route recomputed the whole estate on every request.
The fallback key is the snapshot's own row (scan id, created_at, node and edge
counts), so a re-saved snapshot misses the cache instead of replaying old counts.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import graph_rollup_cache
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def _graph(accounts: int) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="fp-scan", tenant_id="default", created_at=f"2026-10-0{accounts}T00:00:00+00:00")
    graph.add_node(UnifiedNode(id="org:o", entity_type=EntityType.ORG, label="o"))
    for index in range(accounts):
        graph.add_node(UnifiedNode(id=f"account:{index}", entity_type=EntityType.ACCOUNT, label=str(index)))
        graph.add_edge(UnifiedEdge(source="org:o", target=f"account:{index}", relationship=RelationshipType.CONTAINS))
    return graph


@pytest.fixture
def ungenerated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.setattr(graph_rollup_cache, "_CACHE", type(graph_rollup_cache._CACHE)())
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(_graph(2))
    # A backend that cannot pin a generation (the 501 path) yields no identity.
    monkeypatch.setattr("agent_bom.api.routes.graph.optional_generation", lambda *_args, **_kwargs: None)
    loads: list[str] = []
    original = store.load_rollup_graph

    def counting_load(**kwargs):
        loads.append(kwargs.get("scan_id", ""))
        return original(**kwargs)

    monkeypatch.setattr(store, "load_rollup_graph", counting_load)
    set_graph_store(store)
    try:
        yield store, loads
    finally:
        set_graph_store(None)  # type: ignore[arg-type]


def test_rollup_without_generation_is_cached_and_invalidated_by_resave(ungenerated_store) -> None:
    store, loads = ungenerated_store
    client = TestClient(app)

    first = client.get("/v1/graph/rollup")
    second = client.get("/v1/graph/rollup")
    assert first.status_code == second.status_code == 200, first.text
    assert first.json()["top_level"][0]["direct_child_count"] == 2
    assert second.json() == first.json()
    assert len(loads) == 1

    store.save_graph(_graph(3))
    third = client.get("/v1/graph/rollup")
    assert third.status_code == 200
    assert third.json()["top_level"][0]["direct_child_count"] == 3
    assert len(loads) == 2
