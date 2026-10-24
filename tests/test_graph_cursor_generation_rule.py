"""One continuation rule for /v1/graph and /v1/graph/attack-paths.

The cursor carries the snapshot generation, so ``snapshot_generation`` is
optional on a continuation; a supplied one that disagrees is a 409.
"""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType
from tests.test_graph_attack_path_cursor import _three_path_graph
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def _node_graph(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="shared-scan", created_at="2026-09-25T00:00:00Z")
    for index in range(3):
        graph.add_node(UnifiedNode(id=f"package:{index}", entity_type=EntityType.PACKAGE, label=f"p{index}", risk_score=float(index)))
    return graph


def _continuations(client, route: str, headers: dict, page_key: str) -> None:
    params = {"scan_id": "shared-scan", "limit": 1}
    first = client.get(route, params=params, headers=headers)
    assert first.status_code == 200, first.text
    body = first.json()
    cursor, generation = body["pagination"]["next_cursor"], body["snapshot_generation"]
    assert cursor and generation
    for extra in ({}, {"snapshot_generation": generation}):
        response = client.get(route, params=params | {"cursor": cursor, **extra}, headers=headers)
        assert response.status_code == 200, (extra, response.text)
        assert response.json()[page_key]
    mismatch = client.get(route, params=params | {"cursor": cursor, "snapshot_generation": "other-generation"}, headers=headers)
    assert mismatch.status_code == 409, mismatch.text


def test_node_pages_continue_from_the_cursor_alone(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_node_graph("tenant-a"))
    _continuations(client, "/v1/graph", headers["tenant-a"], "nodes")
    cursor = client.get("/v1/graph", params={"scan_id": "shared-scan", "limit": 1}, headers=headers["tenant-a"]).json()["pagination"][
        "next_cursor"
    ]
    store.save_graph(_node_graph("tenant-a"))
    replaced = client.get("/v1/graph", params={"scan_id": "shared-scan", "limit": 1, "cursor": cursor}, headers=headers["tenant-a"])
    assert replaced.status_code == 409, replaced.text


def test_attack_path_pages_accept_a_matching_generation(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_three_path_graph("tenant-a"))
    _continuations(client, "/v1/graph/attack-paths", headers["tenant-a"], "attack_paths")
