"""Default impact depth covers every materialized attack path ending at the node."""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401

_CHAIN = [
    ("agent:far", EntityType.AGENT),
    ("server:etl", EntityType.SERVER),
    ("container:workload", EntityType.CONTAINER),
    ("container:image", EntityType.CONTAINER),
    ("pkg:pillow", EntityType.PACKAGE),
    ("vuln:CVE-2023-4863", EntityType.VULNERABILITY),
]


def _graph(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="depth-scan", created_at="2026-10-18T00:00:00Z")
    for node_id, kind in _CHAIN:
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    relationships = [
        RelationshipType.USES,
        RelationshipType.HOSTED_ON,
        RelationshipType.DEPENDS_ON,
        RelationshipType.DEPENDS_ON,
        RelationshipType.VULNERABLE_TO,
    ]
    for (source, _), (target, _), relationship in zip(_CHAIN, _CHAIN[1:], relationships):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, traversable=True))
    graph.attack_paths.append(
        AttackPath(
            source="agent:far",
            target="vuln:CVE-2023-4863",
            hops=[node_id for node_id, _ in _CHAIN],
            edges=[relationship.value for relationship in relationships],
            vuln_ids=["CVE-2023-4863"],
        )
    )
    return graph


def test_default_impact_reaches_every_agent_with_a_materialized_path(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a"))
    body = client.get(
        "/v1/graph/impact", params={"node": "vuln:CVE-2023-4863", "scan_id": "depth-scan"}, headers=headers["tenant-a"]
    ).json()
    assert "agent:far" in body["affected_nodes"]
    assert body["max_depth"] == 5
    assert body["depth_basis"] == "longest_materialized_path"


def test_explicit_depth_is_honoured_and_labelled(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a"))
    params = {"node": "vuln:CVE-2023-4863", "scan_id": "depth-scan", "max_depth": 2}
    body = client.get("/v1/graph/impact", params=params, headers=headers["tenant-a"]).json()
    assert "agent:far" not in body["affected_nodes"]
    assert body["max_depth"] == 2
    assert body["depth_basis"] == "requested"


def test_node_without_paths_keeps_the_default_depth(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a"))
    body = client.get("/v1/graph/impact", params={"node": "server:etl", "scan_id": "depth-scan"}, headers=headers["tenant-a"]).json()
    assert body["max_depth"] == 4
    assert body["depth_basis"] == "default"
