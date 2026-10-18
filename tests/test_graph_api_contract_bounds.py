"""Graph and runtime read contracts: honest final pages, 404 on foreign snapshots, bounded inputs."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

pytestmark = pytest.mark.graph_contract("warn")


def _graph(tenant: str, scan: str, count: int = 5) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id=scan)
    graph.add_node(
        UnifiedNode(id="agent:root", entity_type=EntityType.AGENT, label=f"needle {tenant} root", compliance_tags=["OWASP-LLM01"])
    )
    for index in range(count):
        node = UnifiedNode(id=f"pkg:{index}", entity_type=EntityType.PACKAGE, label=f"needle pkg {index}")
        graph.add_node(node)
        graph.add_edge(UnifiedEdge(source="agent:root", target=node.id, relationship=RelationshipType.USES))
    return graph


@pytest.fixture
def client(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("tenant-a", "scan-a1"))
    store.save_graph(_graph("tenant-a", "scan-a2", count=6))
    store.save_graph(_graph("tenant-b", "scan-b1"))
    enable_trusted_proxy_env()
    set_graph_store(store)
    try:
        with TestClient(app, headers=proxy_headers(tenant="tenant-a")) as test_client:
            yield test_client
    finally:
        set_graph_store(None)
        disable_trusted_proxy_env()


def _walk(client: TestClient, path: str, params: dict) -> list[dict]:
    pages, cursor, generation = [], None, None
    while True:
        query = dict(params)
        if cursor:
            query.update(cursor=cursor)
            if generation:
                query.update(snapshot_generation=generation)
        response = client.get(path, params=query)
        assert response.status_code == 200, response.text
        body = response.json()
        pages.append(body)
        generation = body.get("snapshot_generation")
        cursor = (body.get("pagination") or {}).get("next_cursor")
        if not cursor:
            return pages


def test_final_keyset_graph_page_is_complete(client):
    pages = _walk(client, "/v1/graph", {"scan_id": "scan-a1", "limit": 2})
    assert len(pages) > 1
    assert pages[0]["completeness"]["truncated"] is True
    final = pages[-1]
    assert final["pagination"]["has_more"] is False
    assert final["completeness"]["complete"] is True
    assert final["completeness"]["truncated"] is False
    assert "reason" not in final["completeness"]
    assert sum(len(page["nodes"]) for page in pages) >= 6


def test_final_keyset_search_page_is_complete(client):
    pages = _walk(client, "/v1/graph/search", {"q": "needle", "scan_id": "scan-a1", "limit": 2})
    assert len(pages) > 1
    final = pages[-1]
    assert final["pagination"]["has_more"] is False
    assert final["completeness"]["complete"] is True


@pytest.mark.parametrize("scan_id", ["no-such-scan", "scan-b1"])
@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/v1/graph/edges/changes", {"old": "scan-a1"}),
        ("/v1/graph/compliance", {}),
        ("/v1/graph/search", {"q": "needle"}),
    ],
)
def test_unknown_or_foreign_scan_id_is_404(client, path, params, scan_id):
    query = dict(params)
    query["new" if path.endswith("changes") else "scan_id"] = scan_id
    response = client.get(path, params=query)
    assert response.status_code == 404, response.text


def test_known_scan_ids_still_answer(client):
    assert client.get("/v1/graph/edges/changes", params={"old": "scan-a1", "new": "scan-a2"}).status_code == 200
    assert client.get("/v1/graph/compliance", params={"scan_id": "scan-a2"}).status_code == 200
    search = client.get("/v1/graph/search", params={"q": "needle", "scan_id": "scan-a2"})
    assert search.status_code == 200 and search.json()["pagination"]["total"] == 7


@pytest.mark.parametrize("path", ["/v1/graph/snapshots", "/v1/graph/history"])
def test_window_days_upper_bound_is_422(client, path):
    assert client.get(path, params={"window_days": 10**9}).status_code == 422
    assert client.get(path, params={"window_days": 3650}).status_code == 200


@pytest.mark.parametrize("path", ["/v1/runtime/sessions", "/v1/runtime/observations", "/v1/runtime/trace-explorer"])
def test_runtime_offset_overflow_is_422(client, path):
    assert client.get(path, params={"offset": 10}).status_code == 200
    response = client.get(path, params={"offset": 2**63})
    assert response.status_code == 422, response.text


def test_graph_query_roots_are_bounded(client):
    response = client.post("/v1/graph/query", json={"roots": [f"n:{i}" for i in range(501)], "scan_id": "scan-a1"})
    assert response.status_code == 422
