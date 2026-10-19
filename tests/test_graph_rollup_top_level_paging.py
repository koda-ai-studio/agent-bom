"""The roll-up top level pages like its drill-down.

``limit`` applied to drill-down only, so at 115k nodes ``rollup?limit=100``
returned all 6,242 top-level entries (3.6 MB). The top level is now ranked
over every entry and paged by ``offset``/``limit`` with an honest
``pagination`` block and ``completeness``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import graph_rollup_cache, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")

_ORGS = 7


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="paging-scan", tenant_id="default", created_at="2026-10-18T00:00:00+00:00")
    for index in range(_ORGS):
        org, account = f"org:{index}", f"account:{index}"
        graph.add_node(UnifiedNode(id=org, entity_type=EntityType.ORG, label=org))
        graph.add_node(UnifiedNode(id=account, entity_type=EntityType.ACCOUNT, label=account))
        graph.add_edge(UnifiedEdge(source=org, target=account, relationship=RelationshipType.CONTAINS))
        # Containers with more descendants rank first, so the order is not alphabetical.
        for child in range(index):
            store_id = f"data_store:{index}-{child}"
            graph.add_node(UnifiedNode(id=store_id, entity_type=EntityType.DATA_STORE, label=store_id))
            graph.add_edge(UnifiedEdge(source=account, target=store_id, relationship=RelationshipType.CONTAINS))
    return graph


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.setattr(graph_rollup_cache, "_CACHE", type(graph_rollup_cache._CACHE)())
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(_graph())
    # Current-estate reads join graph snapshots with completed scan jobs.
    # Keep both stores local so unrelated jobs cannot replace this graph.
    monkeypatch.setattr(stores, "_store", InMemoryJobStore())
    monkeypatch.setattr(stores, "_graph_store", store)
    yield TestClient(app)


def _ids(body: dict) -> list[str]:
    return [row["id"] for row in body["top_level"]]


def test_top_level_honours_limit_with_honest_pagination(client) -> None:
    body = client.get("/v1/graph/rollup", params={"limit": 3}).json()

    assert _ids(body) == ["org:6", "org:5", "org:4"]
    assert body["pagination"] == {"offset": 0, "limit": 3, "returned": 3, "total": _ORGS, "has_more": True, "next_offset": 3}
    assert body["summary"]["top_level_count"] == _ORGS
    assert body["summary"]["returned_top_level_count"] == 3
    assert body["completeness"]["truncated"] is True
    assert body["completeness"]["total"] == _ORGS
    assert body["completeness"]["reason"] == "top_level_page_limit"


def test_top_level_pages_are_disjoint_and_cover_the_whole_ranking(client) -> None:
    whole = _ids(client.get("/v1/graph/rollup", params={"limit": 1000}).json())
    first = client.get("/v1/graph/rollup", params={"limit": 3}).json()
    generation = first["snapshot_generation"]
    pages: list[str] = _ids(first)
    offset: int | None = first["pagination"]["next_offset"]
    while offset is not None:
        body = client.get("/v1/graph/rollup", params={"limit": 3, "offset": offset, "snapshot_generation": generation}).json()
        pages.extend(_ids(body))
        offset = body["pagination"]["next_offset"]

    assert len(whole) == _ORGS
    assert pages == whole


def test_a_continuation_must_pin_the_first_page_generation(client) -> None:
    assert client.get("/v1/graph/rollup", params={"limit": 3, "offset": 3}).status_code in {409, 422}


def test_last_page_reports_no_more(client) -> None:
    generation = client.get("/v1/graph/rollup", params={"limit": 3}).json()["snapshot_generation"]
    body = client.get("/v1/graph/rollup", params={"limit": 3, "offset": 6, "snapshot_generation": generation}).json()

    assert _ids(body) == ["org:0"]
    assert body["pagination"]["has_more"] is False
    assert body["pagination"]["next_offset"] is None


def test_unpaged_estate_is_complete(client) -> None:
    body = client.get("/v1/graph/rollup", params={"limit": 1000}).json()

    assert body["completeness"]["complete"] is True
    assert body["pagination"]["has_more"] is False
