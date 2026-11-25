"""A compromised compute host reaches what runs on it; a scope that "hosts" inventory does not."""

from __future__ import annotations

import pytest

from agent_bom.graph.attack_path_fusion import compute_fused_attack_paths, traversal_steps
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType
from agent_bom.graph.types import RelationshipType as R

pytestmark = pytest.mark.graph_contract("warn")


def _estate(host: UnifiedNode, *, hosting: str) -> UnifiedGraph:
    """Internet-exposed host -> agent -> MCP server -> credential -> customer data, hosting recorded either way."""
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(host)
    g.add_node(UnifiedNode(id="agent:triage", entity_type=EntityType.AGENT, label="support-triage-agent"))
    g.add_node(UnifiedNode(id="server:tickets", entity_type=EntityType.SERVER, label="ticketing MCP"))
    g.add_node(UnifiedNode(id="cred:tickets", entity_type=EntityType.CREDENTIAL_REF, label="TICKETING_API_KEY"))
    g.add_node(
        UnifiedNode(
            id="data:tickets", entity_type=EntityType.DATA_STORE, label="customer-ticket-archive", attributes={"data_sensitivity": "pii"}
        )
    )
    if hosting == "hosted_on":
        g.add_edge(UnifiedEdge(source="agent:triage", target=host.id, relationship=R.HOSTED_ON))
    else:
        g.add_edge(UnifiedEdge(source=host.id, target="agent:triage", relationship=R.HOSTS))
    g.add_edge(UnifiedEdge(source="agent:triage", target="server:tickets", relationship=R.USES))
    g.add_edge(UnifiedEdge(source="server:tickets", target="cred:tickets", relationship=R.EXPOSES_CRED))
    g.add_edge(UnifiedEdge(source="cred:tickets", target="data:tickets", relationship=R.CAN_ACCESS))
    return g


def _workload() -> UnifiedNode:
    return UnifiedNode(
        id="container:serving", entity_type=EntityType.CONTAINER, label="model-serving", attributes={"internet_exposed": True}
    )


@pytest.mark.parametrize("hosting", ["hosted_on", "hosts"])
def test_an_exposed_workload_reaches_data_through_the_agent_it_hosts(hosting):
    paths = compute_fused_attack_paths(_estate(_workload(), hosting=hosting))
    chain = next(path for path in paths if path.target == "data:tickets")
    assert chain.hops == ["container:serving", "agent:triage", "server:tickets", "cred:tickets", "data:tickets"]
    assert chain.edges[0] == hosting and chain.credential_exposure == ["TICKETING_API_KEY"]


def test_a_compute_instance_is_a_host_and_a_bucket_is_not():
    instance = UnifiedNode(
        id="res:ec2",
        entity_type=EntityType.CLOUD_RESOURCE,
        label="i-0abc",
        attributes={"internet_exposed": True, "resource_type": "instance"},
    )
    assert [nxt for _, nxt in traversal_steps(_estate(instance, hosting="hosted_on"), "res:ec2")] == ["agent:triage"]
    bucket = UnifiedNode(
        id="res:bucket",
        entity_type=EntityType.CLOUD_RESOURCE,
        label="logs",
        attributes={"internet_exposed": True, "resource_type": "bucket"},
    )
    assert traversal_steps(_estate(bucket, hosting="hosted_on"), "res:bucket") == []


@pytest.mark.parametrize("scope_type", [EntityType.ENVIRONMENT, EntityType.ACCOUNT, EntityType.CLUSTER])
def test_a_scope_that_hosts_its_inventory_opens_no_path(scope_type):
    scope = UnifiedNode(id="scope:prod", entity_type=scope_type, label="Production", attributes={"internet_exposed": True})
    graph = _estate(scope, hosting="hosts")
    assert traversal_steps(graph, "scope:prod") == []
    assert not [path for path in compute_fused_attack_paths(graph) if path.source == "scope:prod"]


def test_a_hosted_agent_does_not_step_back_to_its_host():
    graph = _estate(_workload(), hosting="hosted_on")
    assert "container:serving" not in [nxt for _, nxt in traversal_steps(graph, "agent:triage")]
