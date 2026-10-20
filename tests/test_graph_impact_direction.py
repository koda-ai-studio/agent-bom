"""Path impact answers both 'what depends on this' and 'what this can reach', with the nodes behind each count."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def _chain(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="impact-scan", created_at="2026-10-18T00:00:00Z")
    for node_id, kind, label in [
        ("agent:a", EntityType.AGENT, "agent-a"),
        ("server:s", EntityType.SERVER, "server-s"),
        ("tool:t", EntityType.TOOL, "tool-t"),
        ("cred:c", EntityType.CREDENTIAL, "API_KEY"),
    ]:
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=label))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, traversable=True))
    graph.add_edge(UnifiedEdge(source="server:s", target="tool:t", relationship=RelationshipType.PROVIDES_TOOL, traversable=True))
    graph.add_edge(UnifiedEdge(source="server:s", target="cred:c", relationship=RelationshipType.EXPOSES_CRED, traversable=True))
    return graph


def test_impact_reverse_stays_the_default_and_lists_its_nodes(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_chain("tenant-a"))
    body = client.get("/v1/graph/impact", params={"node": "server:s", "scan_id": "impact-scan"}, headers=headers["tenant-a"]).json()
    assert body["affected_nodes"] == ["agent:a"]
    assert body["direction"] == "reverse"
    assert body["interpretation"]["basis"] == "recorded_reverse_reachability"
    assert body["affected_nodes_detail"] == [{"id": "agent:a", "label": "agent-a", "entity_type": "agent", "depth": 1}]


def test_impact_forward_reports_what_the_node_can_reach(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_chain("tenant-a"))
    body = client.get(
        "/v1/graph/impact", params={"node": "server:s", "scan_id": "impact-scan", "direction": "forward"}, headers=headers["tenant-a"]
    ).json()
    assert "cred:c" in body["affected_nodes"]
    assert "agent:a" not in body["affected_nodes"]
    assert body["direction"] == "forward"
    assert body["interpretation"]["basis"] == "recorded_forward_reachability"
    assert "credential" in {node["entity_type"] for node in body["affected_nodes_detail"]}


def test_impact_rejects_an_unknown_direction_and_other_tenants(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_chain("tenant-a"))
    bad = client.get("/v1/graph/impact", params={"node": "server:s", "direction": "sideways"}, headers=headers["tenant-a"])
    assert bad.status_code == 422
    other = client.get("/v1/graph/impact", params={"node": "server:s", "scan_id": "impact-scan"}, headers=headers["tenant-b"])
    assert other.status_code in {403, 404}
    assert "agent-a" not in other.text
