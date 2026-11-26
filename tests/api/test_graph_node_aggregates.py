"""A node's aggregate is the one its roll-up entry carries, on every read that reports it."""

from __future__ import annotations

from fastapi.testclient import TestClient

from agent_bom.api.routes.graph_routes.node_aggregates import MAX_NODE_AGGREGATES
from agent_bom.graph.types import GraphSemanticLayer
from tests._demo_estate_fixtures import VIEWER

_LAYERS = {layer.value for layer in GraphSemanticLayer}


def _get(client: TestClient, path: str, **params: object) -> dict:
    response = client.get(path, headers=VIEWER, params=params)
    assert response.status_code == 200, (path, response.text)
    return response.json()


def test_node_aggregates_equal_the_rollup_entries(shared_demo_estate_client: TestClient) -> None:
    client = shared_demo_estate_client
    rollup = _get(client, "/v1/graph/rollup")
    entries = {row["id"]: row for row in rollup["top_level"]}
    parent = next(row for row in rollup["top_level"] if row["has_children"])
    drill = _get(client, "/v1/graph/rollup", node=parent["id"], scan_id=rollup["scan_id"])
    entries.update({row["id"]: row for row in drill["children"]})
    assert drill["node"]["semantic_layer"] in _LAYERS
    assert all(row["semantic_layer"] in _LAYERS for row in entries.values())

    ids = list(entries)[:MAX_NODE_AGGREGATES]
    body = _get(client, "/v1/graph/node-aggregates", node_id=ids, scan_id=rollup["scan_id"])
    assert body["missing_node_ids"] == []
    assert [row["node_id"] for row in body["aggregates"]] == ids
    assert any(row["aggregate"]["issue_count"] for row in body["aggregates"])
    for row in body["aggregates"]:
        entry = entries[row["node_id"]]
        assert row["aggregate"] == entry["aggregate"], row["node_id"]
        assert row["semantic_layer"] == entry["semantic_layer"]


def test_path_hops_get_their_aggregates(shared_demo_estate_client: TestClient) -> None:
    client = shared_demo_estate_client
    queue = _get(client, "/v1/graph/attack-paths", limit=1)
    hops = queue["attack_paths"][0]["hops"]
    body = _get(client, "/v1/graph/node-aggregates", node_id=hops, scan_id=queue["scan_id"])
    assert [row["node_id"] for row in body["aggregates"]] == list(dict.fromkeys(hops))
    assert all(row["semantic_layer"] in _LAYERS for row in body["aggregates"])
    assert any(row["aggregate"]["issue_count"] > 0 for row in body["aggregates"])


def test_unknown_ids_are_reported_not_invented(shared_demo_estate_client: TestClient) -> None:
    body = _get(shared_demo_estate_client, "/v1/graph/node-aggregates", node_id=["no-such-node"])
    assert body["aggregates"] == []
    assert body["missing_node_ids"] == ["no-such-node"]


def test_request_is_bounded(shared_demo_estate_client: TestClient) -> None:
    ids = [f"n{index}" for index in range(MAX_NODE_AGGREGATES + 1)]
    response = shared_demo_estate_client.get("/v1/graph/node-aggregates", headers=VIEWER, params={"node_id": ids})
    assert response.status_code == 422


def test_scope_findings_reconcile_exact_issue_count(shared_demo_estate_client: TestClient) -> None:
    client = shared_demo_estate_client
    rollup = _get(client, "/v1/graph/rollup")
    scope = min(
        (row for row in rollup["top_level"] if row["aggregate"]["issue_count"] > 0), key=lambda row: row["aggregate"]["issue_count"]
    )
    params = {"scan_id": rollup["scan_id"], "node_id": scope["id"], "limit": 2}
    first = _get(client, "/v1/graph/scope-findings", **params)
    assert first["total"] == scope["aggregate"]["issue_count"]
    assert len(first["findings"]) == min(2, first["total"])
    rows = list(first["findings"])
    for offset in range(2, first["total"], 2):
        page = _get(
            client,
            "/v1/graph/scope-findings",
            **params,
            offset=offset,
            snapshot_generation=first["snapshot_generation"],
            finding_revision=first["finding_revision"],
        )
        rows.extend(page["findings"])
    assert len({row["issue_key"] for row in rows}) == first["total"]
    assert all(row["node_ids"] and row["label"] for row in rows)


def test_scope_findings_unknown_scope_is_not_clean(shared_demo_estate_client: TestClient) -> None:
    response = shared_demo_estate_client.get("/v1/graph/scope-findings", headers=VIEWER, params={"node_id": "missing"})
    assert response.status_code == 404
