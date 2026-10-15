"""The attack-path queue must be walkable by cursor and count what it serves."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.api.routes.graph_routes.payloads import _serialize_attack_path_queue
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def _three_path_graph(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="shared-scan", created_at="2026-09-25T00:00:00Z")
    source = "principal:reader"
    graph.add_node(UnifiedNode(id=source, entity_type=EntityType.SERVICE_ACCOUNT, label="reader"))
    paths = []
    for index in range(3):
        target = f"data:store-{index}"
        graph.add_node(UnifiedNode(id=target, entity_type=EntityType.DATA_STORE, label=target))
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.CAN_ACCESS))
        path = AttackPath(source=source, target=target, hops=[source, target], edges=["can_access"], composite_risk=50.0 - index)
        paths.append(annotate_attack_path_evidence(path, graph))
    graph.attack_paths = paths
    return graph


def test_has_more_always_carries_a_cursor_that_walks_the_whole_queue(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_three_path_graph("tenant-a"))
    params = {"scan_id": "shared-scan", "limit": 1}
    seen: list[str] = []
    page = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()
    while True:
        seen.extend(path["target"] for path in page["attack_paths"])
        pagination = page["pagination"]
        if not pagination["has_more"]:
            assert pagination["next_cursor"] == ""
            break
        assert pagination["next_cursor"], pagination
        response = client.get("/v1/graph/attack-paths", params=params | {"cursor": pagination["next_cursor"]}, headers=headers["tenant-a"])
        assert response.status_code == 200, response.text
        page = response.json()
        assert page["pagination"]["cursor"] == pagination["next_cursor"]
    assert sorted(seen) == ["data:store-0", "data:store-1", "data:store-2"]


def test_cursor_is_bound_to_its_tenant_query_and_generation(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_three_path_graph("tenant-a"))
    params = {"scan_id": "shared-scan", "limit": 1}
    cursor = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()["pagination"]["next_cursor"]
    assert client.get("/v1/graph/attack-paths", params=params | {"cursor": "not-a-cursor"}, headers=headers["tenant-a"]).status_code == 400
    assert client.get("/v1/graph/attack-paths", params=params | {"cursor": cursor}, headers=headers["tenant-b"]).status_code == 400
    filtered = params | {"cursor": cursor, "min_severity": "high"}
    assert client.get("/v1/graph/attack-paths", params=filtered, headers=headers["tenant-a"]).status_code == 400
    store.save_graph(_three_path_graph("tenant-a"))
    assert client.get("/v1/graph/attack-paths", params=params | {"cursor": cursor}, headers=headers["tenant-a"]).status_code == 409


def _queue(stats: dict, *, total: int, complete: bool) -> dict:
    ranked = SimpleNamespace(snapshot_total=total, ranking={"complete": complete})
    return _serialize_attack_path_queue(
        scan_id="s",
        tenant="t",
        created_at="",
        nodes=[],
        path_edges=[],
        paths=[],
        total=total,
        offset=0,
        limit=10,
        stats=stats,
        path_source="derived_graph_paths",
        materialized_paths=0,
        derived_paths=total,
        ranked=ranked,
    )


def test_stats_attack_path_count_matches_the_served_queue_total() -> None:
    payload = _queue({"attack_path_count": 2930, "max_attack_path_risk": 80.0}, total=2931, complete=True)
    assert payload["stats"]["attack_path_count"] == payload["pagination"]["total"] == 2931
    assert payload["stats"]["max_attack_path_risk"] == 80.0


def test_stats_keep_the_snapshot_count_when_the_queue_total_is_only_a_lower_bound() -> None:
    payload = _queue({"attack_path_count": 5000, "max_attack_path_risk": 80.0}, total=1000, complete=False)
    assert payload["stats"]["attack_path_count"] == 5000
