"""The cross-vendor slice of the attack-path queue: vendor pairs read from recorded node attributes."""

from __future__ import annotations

from agent_bom.api.read_models import STRICT_CONTRACT
from agent_bom.api.read_models.graph_vendor_paths import GraphCrossVendorPathsResponse
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from agent_bom.graph.path_vendors import path_vendor_pair
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def _node(node_id: str, entity_type: EntityType, vendor: str = "") -> UnifiedNode:
    attributes = {"cloud_provider": vendor} if vendor else {}
    return UnifiedNode(id=node_id, entity_type=entity_type, label=node_id.rsplit(":", 1)[-1], attributes=attributes)


def _graph(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="vendor-scan", created_at="2026-10-20T00:00:00Z")
    nodes = [
        _node("snowflake:table:T", EntityType.DATA_STORE, "snowflake"),
        _node("snowflake:storage_integration:I", EntityType.CLOUD_RESOURCE, "snowflake"),
        _node("aws:bucket:B", EntityType.DATA_STORE, "aws"),
        _node("github:repository:R", EntityType.SERVICE_ACCOUNT, "github"),
        _node("agent:a", EntityType.AGENT),
        _node("server:s", EntityType.SERVER, "mcp"),
        _node("aws:role:X", EntityType.ROLE, "aws"),
    ]
    for node in nodes:
        graph.add_node(node)
    chains = [
        (["snowflake:table:T", "snowflake:storage_integration:I", "aws:bucket:B"], ["depends_on", "can_access"], 52.0),
        (["github:repository:R", "aws:role:X"], ["assumes"], 60.0),
        (["agent:a", "server:s"], ["uses"], 95.0),
        (["aws:role:X", "aws:bucket:B"], ["can_access"], 90.0),
    ]
    paths = []
    for hops, edges, risk in chains:
        for source, target, rel in zip(hops, hops[1:], edges):
            graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType(rel)))
        path = AttackPath(source=hops[0], target=hops[-1], hops=hops, edges=edges, composite_risk=risk)
        paths.append(annotate_attack_path_evidence(path, graph))
    graph.attack_paths = paths
    return graph


def test_vendor_pair_reads_the_path_endpoints_only():
    graph = _graph("t")
    pairs = [path_vendor_pair(path, graph.nodes) for path in graph.attack_paths]
    assert pairs == [("snowflake", "aws"), ("github", "aws"), None, None]
    # A finding or agent endpoint carries no vendor: vendors on middle hops never make a path cross-vendor.
    through = AttackPath(source="agent:a", target="server:s", hops=["agent:a", "github:repository:R", "aws:role:X", "server:s"], edges=[])
    assert path_vendor_pair(through, graph.nodes) is None


def test_cross_vendor_queue_lists_only_paths_spanning_two_vendors(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a"))
    response = client.get("/v1/graph/attack-paths/cross-vendor", params={"scan_id": "vendor-scan"}, headers=headers["tenant-a"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert {path["target"] for path in body["attack_paths"]} == {"aws:bucket:B", "aws:role:X"}
    assert body["pagination"]["total"] == 2
    assert body["vendor_facets"]["unit"] == "paths"
    assert body["vendor_facets"]["cross_vendor_paths"] == 2
    assert body["vendor_facets"]["snapshot_paths"] == 4
    assert body["vendor_facets"]["pairs"] == [
        {"source_vendor": "github", "target_vendor": "aws", "paths": 1},
        {"source_vendor": "snowflake", "target_vendor": "aws", "paths": 1},
    ]
    GraphCrossVendorPathsResponse.model_validate(body, context={STRICT_CONTRACT: True})
    hop_ids = {node["id"] for node in body["nodes"]}
    assert {"snowflake:table:T", "snowflake:storage_integration:I", "aws:bucket:B"} <= hop_ids


def test_vendor_pair_filter_narrows_and_keeps_facets_whole(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a"))
    params = {"scan_id": "vendor-scan", "source_vendor": "snowflake", "target_vendor": "aws"}
    body = client.get("/v1/graph/attack-paths/cross-vendor", params=params, headers=headers["tenant-a"]).json()
    assert [path["hops"] for path in body["attack_paths"]] == [["snowflake:table:T", "snowflake:storage_integration:I", "aws:bucket:B"]]
    assert body["pagination"]["total"] == 1
    assert body["vendor_facets"]["cross_vendor_paths"] == 2
    assert body["vendor_facets"]["selected"] == {"source_vendor": "snowflake", "target_vendor": "aws"}


def test_cross_vendor_queue_never_reads_another_tenant(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a"))
    response = client.get("/v1/graph/attack-paths/cross-vendor", params={"scan_id": "vendor-scan"}, headers=headers["tenant-b"])
    body = response.json()
    assert body.get("attack_paths", []) == []
    assert "snowflake:table:T" not in response.text
