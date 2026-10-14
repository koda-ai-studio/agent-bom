"""Bounded ``/v1/graph/diff`` views: summary by default, filtered detail pages, capped full lists."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.diff_view import full_view


def _graph(scan_id: str, created_at: str, *, tenant_id: str = "default", current: bool) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id, created_at=created_at)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s", risk_score=2.0 if current else 1.0))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    if current:
        graph.add_node(UnifiedNode(id="vuln:crit", entity_type=EntityType.VULNERABILITY, label="crit", severity="critical", risk_score=9.5))
        graph.add_node(UnifiedNode(id="vuln:low", entity_type=EntityType.VULNERABILITY, label="low", severity="low", risk_score=1.0))
        graph.add_node(UnifiedNode(id="cred:key", entity_type=EntityType.CREDENTIAL, label="API_KEY"))
        graph.add_edge(UnifiedEdge(source="server:s", target="vuln:crit", relationship=RelationshipType.VULNERABLE_TO))
        graph.add_edge(UnifiedEdge(source="server:s", target="vuln:low", relationship=RelationshipType.VULNERABLE_TO))
        graph.add_edge(UnifiedEdge(source="server:s", target="cred:key", relationship=RelationshipType.EXPOSES_CRED))
    else:
        graph.add_node(UnifiedNode(id="agent:gone", entity_type=EntityType.AGENT, label="agent-gone"))
        graph.add_edge(UnifiedEdge(source="agent:gone", target="server:s", relationship=RelationshipType.USES))
    return graph


@pytest.fixture()
def client(tmp_path) -> Iterator[TestClient]:
    store = SQLiteGraphStore(tmp_path / "diff.db")
    store.save_graph(_graph("diff-old", "2026-09-01T00:00:00Z", current=False))
    store.save_graph(_graph("diff-new", "2026-09-02T00:00:00Z", current=True))
    store.save_graph(_graph("other-tenant-old", "2026-09-01T00:00:00Z", tenant_id="tenant-b", current=False))
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(original)  # type: ignore[arg-type]


def _get(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get("/v1/graph/diff", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_default_is_a_summary_of_the_latest_two_snapshots(client: TestClient) -> None:
    body = _get(client)
    assert (body["view"], body["old"], body["new"]) == ("summary", "diff-old", "diff-new")
    assert "nodes_added" not in body and "change_kind_index" not in body
    summary = body["summary"]
    assert summary["totals"] == {"nodes": {"added": 3, "removed": 1, "changed": 1}, "edges": {"added": 3, "removed": 1, "changed": 0}}
    assert summary["total_changes"] == 9
    assert summary["nodes_by_entity_type"]["vulnerability"] == {"added": 2, "removed": 0, "changed": 0}
    assert summary["nodes_by_entity_type"]["server"] == {"added": 0, "removed": 0, "changed": 1}
    assert summary["edges_by_relationship"]["uses"] == {"added": 0, "removed": 1, "changed": 0}
    highlights = summary["highlights"]
    assert [row["id"] for row in highlights["new_critical_findings"]["top"]] == ["vuln:crit"]
    assert [row["id"] for row in highlights["new_credential_reach"]["top"]] == ["server:s|cred:key|exposes_cred"]
    assert highlights["new_attack_paths"]["status"] in {"not_materialized", "complete"}
    assert body["completeness"]["complete"] is True
    assert body == _get(client, old="diff-old", new="diff-new")


def test_detail_cursor_walk_returns_every_row_once_in_stable_order(client: TestClient) -> None:
    whole = _get(client, view="detail", limit=200)
    assert whole["total"] == 9 and whole["pagination"]["has_more"] is False
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, Any] = {"view": "detail", "limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = _get(client, **params)
        assert page["total"] == 9
        seen.extend(row["id"] for row in page["items"])
        cursor = page["pagination"]["next_cursor"]
        if not cursor:
            break
    assert seen == [row["id"] for row in whole["items"]]
    assert len(seen) == len(set(seen)) == 9
    kinds = [(row["kind"], row["change"]) for row in whole["items"]]
    assert kinds == sorted(kinds, key=lambda item: (item[0] != "node", ["added", "removed", "changed"].index(item[1])))


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"change": "removed"}, ["agent:gone", "agent:gone|server:s|uses"]),
        ({"entity_type": "vulnerability"}, ["vuln:crit", "vuln:low"]),
        ({"relationship": "exposes_cred"}, ["server:s|cred:key|exposes_cred"]),
        ({"node_id": "cred:key"}, ["cred:key", "server:s|cred:key|exposes_cred"]),
        ({"kind": "node", "change": "changed"}, ["server:s"]),
    ],
)
def test_detail_filters(client: TestClient, params: dict[str, str], expected: list[str]) -> None:
    body = _get(client, view="detail", **params)
    assert [row["id"] for row in body["items"]] == expected
    assert body["total"] == len(expected)
    assert body["filters"] == params


def test_changed_node_rows_carry_entity_type_and_deltas(client: TestClient) -> None:
    row = _get(client, view="detail", change="changed", kind="node")["items"][0]
    assert row["entity_type"] == "server" and row["label"] == "server-s" and row["risk_score"] == 2.0
    # A risk-score change is a node change without a drift-attribute delta.
    assert row["deltas"] == []


@pytest.mark.parametrize(
    ("params", "status"),
    [
        ({"old": "diff-old"}, 422),
        ({"old": "diff-old", "new": "missing"}, 404),
        ({"old": "other-tenant-old", "new": "diff-new"}, 404),
        ({"view": "everything"}, 422),
        ({"view": "detail", "limit": 0}, 422),
        ({"view": "detail", "cursor": "not-a-cursor"}, 422),
    ],
)
def test_invalid_requests_are_rejected(client: TestClient, params: dict[str, Any], status: int) -> None:
    assert client.get("/v1/graph/diff", params=params).status_code == status


def test_cursor_is_bound_to_its_filters(client: TestClient) -> None:
    cursor = _get(client, view="detail", limit=1)["pagination"]["next_cursor"]
    response = client.get("/v1/graph/diff", params={"view": "detail", "limit": 1, "change": "added", "cursor": cursor})
    assert response.status_code == 422


def test_full_view_keeps_the_legacy_shape_with_flags(client: TestClient) -> None:
    body = _get(client, view="full")
    assert body["truncated"] is False and body["complete"] is True
    assert body["change_kind_index"]["nodes"]["vuln:crit"] == "new"
    assert body["change_kind_index"]["edges"]["agent:gone|server:s|uses"] == "removed"
    assert all("attributes" not in node for node in body["nodes_added"])
    assert body["summary"]["totals"]["nodes"]["added"] == 3


def test_full_view_caps_rows_and_bytes() -> None:
    diff = {
        "nodes_added": [{"id": f"vuln:{index}", "entity_type": "vulnerability", "attributes": {"x": "y" * 50}} for index in range(50)],
        "nodes_removed": [],
        "nodes_changed": [],
        "edges_added": [["a", f"vuln:{index}", "vulnerable_to"] for index in range(50)],
        "edges_removed": [],
        "edges_changed": [],
    }
    from agent_bom.graph.diff_view import diff_rows

    rows = diff_rows(diff)
    capped = full_view(diff, rows, row_cap=30)
    assert capped["truncated"] is True and capped["complete"] is False
    assert capped["returned_changes"] == 30 and capped["total_changes"] == 100
    assert len(capped["nodes_added"]) == 30 and capped["edges_added"] == []
    assert len(capped["change_kind_index"]["nodes"]) == 30
    tiny = full_view(diff, rows, byte_cap=2_000)
    assert tiny["truncated"] is True and tiny["returned_changes"] < 30
