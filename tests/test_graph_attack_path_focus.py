"""A finding's investigation link must open its path wherever it ranks in the queue."""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def _queue_graph(tenant: str, count: int = 30) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="focus-scan", created_at="2026-10-18T00:00:00Z")
    source = "principal:reader"
    graph.add_node(UnifiedNode(id=source, entity_type=EntityType.SERVICE_ACCOUNT, label="reader"))
    paths = []
    for index in range(count):
        target = f"data:store-{index}"
        graph.add_node(UnifiedNode(id=target, entity_type=EntityType.DATA_STORE, label=target))
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.CAN_ACCESS))
        path = AttackPath(source=source, target=target, hops=[source, target], edges=["can_access"], composite_risk=90.0 - index)
        if index == count - 1:
            path.finding_ids = ["finding-last"]
        paths.append(annotate_attack_path_evidence(path, graph))
    graph.attack_paths = paths
    return graph


def test_node_focus_returns_a_path_beyond_the_first_page(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    unfocused = client.get("/v1/graph/attack-paths", params={"scan_id": "focus-scan", "limit": 10}, headers=headers["tenant-a"]).json()
    assert "data:store-29" not in {path["target"] for path in unfocused["attack_paths"]}

    response = client.get(
        "/v1/graph/attack-paths",
        params={"scan_id": "focus-scan", "limit": 10, "node_id": "data:store-29"},
        headers=headers["tenant-a"],
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert [path["target"] for path in body["attack_paths"]] == ["data:store-29"]
    assert body["pagination"]["total"] == 1
    assert body["pagination"]["has_more"] is False
    assert body["focus"] == {"node_id": "data:store-29", "finding_id": None, "resolved_from": None, "covers_all_matches": True}


def test_finding_focus_matches_the_occurrence_and_misses_are_empty_not_errors(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    params = {"scan_id": "focus-scan", "limit": 10}
    found = client.get("/v1/graph/attack-paths", params=params | {"finding_id": "finding-last"}, headers=headers["tenant-a"]).json()
    assert [path["target"] for path in found["attack_paths"]] == ["data:store-29"]
    both = client.get(
        "/v1/graph/attack-paths", params=params | {"finding_id": "finding-last", "node_id": "data:store-3"}, headers=headers["tenant-a"]
    )
    assert both.status_code == 200, both.text
    assert both.json()["attack_paths"] == []
    assert both.json()["pagination"]["total"] == 0


def test_focused_cursor_is_bound_to_its_focus(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    params = {"scan_id": "focus-scan", "limit": 1, "node_id": "principal:reader"}
    first = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()
    assert first["pagination"]["total"] == 30
    cursor = first["pagination"]["next_cursor"]
    assert cursor
    second = client.get("/v1/graph/attack-paths", params=params | {"cursor": cursor}, headers=headers["tenant-a"])
    assert second.status_code == 200, second.text
    assert second.json()["attack_paths"][0]["target"] != first["attack_paths"][0]["target"]
    other_focus = {"scan_id": "focus-scan", "limit": 1, "node_id": "data:store-1", "cursor": cursor}
    assert client.get("/v1/graph/attack-paths", params=other_focus, headers=headers["tenant-a"]).status_code == 400


def test_focus_never_reads_another_tenant(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    response = client.get(
        "/v1/graph/attack-paths", params={"scan_id": "focus-scan", "node_id": "data:store-29"}, headers=headers["tenant-b"]
    )
    body = response.json()
    assert body.get("attack_paths", []) == []
    assert body.get("nodes", []) == []
    assert "principal:reader" not in response.text
