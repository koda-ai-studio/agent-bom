"""Cloud provider inheritance follows recorded containment/hosting edges only."""

from __future__ import annotations

import pytest

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.node import NodeDimensions
from agent_bom.graph.provider_inheritance import inherit_cloud_provider
from agent_bom.graph.rollup import drill_down, rollup_view
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def _node(node_id: str, entity_type: EntityType, label: str, provider: str = "") -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=entity_type, label=label, dimensions=NodeDimensions(cloud_provider=provider))


def _edge(graph: UnifiedGraph, source: str, target: str, relationship: RelationshipType) -> None:
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship))


def _cloud_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="provider-inheritance", tenant_id="default")
    graph.add_node(_node("account:prod", EntityType.ACCOUNT, "prod-workloads", "aws"))
    graph.add_node(_node("env:prod", EntityType.ENVIRONMENT, "production"))
    graph.add_node(_node("cluster:payments", EntityType.CLUSTER, "payments-eks"))
    graph.add_node(_node("container:checkout", EntityType.CONTAINER, "checkout-api"))
    graph.add_node(_node("container:ledger", EntityType.CONTAINER, "ledger-worker"))
    graph.add_node(_node("package:urllib3", EntityType.PACKAGE, "urllib3"))
    graph.add_node(_node("cve:1", EntityType.VULNERABILITY, "CVE-2023-43804"))
    graph.add_node(_node("role:checkout", EntityType.ROLE, "checkout-runtime-role"))
    _edge(graph, "account:prod", "env:prod", RelationshipType.CONTAINS)
    _edge(graph, "env:prod", "cluster:payments", RelationshipType.CONTAINS)
    _edge(graph, "env:prod", "package:urllib3", RelationshipType.CONTAINS)
    _edge(graph, "cluster:payments", "container:checkout", RelationshipType.CONTAINS)
    _edge(graph, "container:ledger", "cluster:payments", RelationshipType.HOSTED_ON)
    _edge(graph, "container:ledger", "package:urllib3", RelationshipType.CONTAINS)
    _edge(graph, "package:urllib3", "cve:1", RelationshipType.VULNERABLE_TO)
    # Authentication is not containment: the role proves nothing about where it lives.
    _edge(graph, "container:checkout", "role:checkout", RelationshipType.AUTHENTICATES_AS)
    return graph


def test_hosted_and_contained_assets_inherit_the_provider_with_a_basis() -> None:
    graph = _cloud_graph()
    stamped = inherit_cloud_provider(graph)

    environment = graph.nodes["env:prod"]
    assert environment.dimensions.cloud_provider == "aws"
    assert environment.attributes["cloud_provider_basis"] == "inherited:contains"
    assert environment.attributes["cloud_provider_source"] == {
        "node_id": "account:prod",
        "label": "prod-workloads",
        "entity_type": "account",
    }
    assert graph.nodes["cluster:payments"].attributes["cloud_provider_source"]["node_id"] == "env:prod"
    for container_id in ("container:checkout", "container:ledger"):
        container = graph.nodes[container_id]
        assert container.dimensions.cloud_provider == "aws"
        assert container.attributes["cloud_provider_source"]["node_id"] == "cluster:payments"
    assert graph.nodes["container:checkout"].attributes["cloud_provider_basis"] == "inherited:contains"
    assert graph.nodes["container:ledger"].attributes["cloud_provider_basis"] == "inherited:hosted_on"
    assert stamped == 4


def test_findings_packages_and_non_containment_neighbours_stay_unset() -> None:
    graph = _cloud_graph()
    inherit_cloud_provider(graph)
    for node_id in ("package:urllib3", "cve:1", "role:checkout"):
        node = graph.nodes[node_id]
        assert node.dimensions.cloud_provider == ""
        assert "cloud_provider_basis" not in node.attributes


def test_declared_provider_is_never_overwritten() -> None:
    graph = _cloud_graph()
    graph.nodes["env:prod"].attributes["cloud_provider"] = "aws"
    graph.nodes["container:checkout"].dimensions.cloud_provider = "aws"
    inherit_cloud_provider(graph)
    assert "cloud_provider_basis" not in graph.nodes["env:prod"].attributes
    assert "cloud_provider_basis" not in graph.nodes["container:checkout"].attributes


def test_conflicting_providers_along_the_chain_leave_it_unset() -> None:
    graph = _cloud_graph()
    graph.nodes["cluster:payments"].dimensions.cloud_provider = "gcp"
    inherit_cloud_provider(graph)
    # account says aws, cluster says gcp: the contained containers cannot be told apart.
    assert graph.nodes["container:checkout"].dimensions.cloud_provider == ""
    assert "cloud_provider_basis" not in graph.nodes["container:checkout"].attributes


def test_two_parents_with_different_providers_leave_it_unset() -> None:
    graph = UnifiedGraph(scan_id="conflict", tenant_id="default")
    graph.add_node(_node("account:aws", EntityType.ACCOUNT, "aws-prod", "aws"))
    graph.add_node(_node("account:gcp", EntityType.ACCOUNT, "gcp-prod", "gcp"))
    graph.add_node(_node("bucket:shared", EntityType.DATA_STORE, "shared"))
    _edge(graph, "account:aws", "bucket:shared", RelationshipType.CONTAINS)
    _edge(graph, "account:gcp", "bucket:shared", RelationshipType.OWNS)
    inherit_cloud_provider(graph)
    assert graph.nodes["bucket:shared"].dimensions.cloud_provider == ""


@pytest.mark.parametrize("reverse", [False, True])
def test_distant_conflicting_hosts_do_not_depend_on_edge_order(reverse) -> None:
    graph = UnifiedGraph(scan_id="deep-hosting")
    for index in range(20):
        graph.add_node(_node(f"container:{index}", EntityType.CONTAINER, f"Container {index}", "gcp" if index == 0 else ""))
    graph.add_node(_node("vm:aws", EntityType.CLOUD_RESOURCE, "AWS host", "aws"))
    indices = list(range(19))
    for index in reversed(indices) if reverse else indices:
        _edge(graph, f"container:{index + 1}", f"container:{index}", RelationshipType.HOSTED_ON)
    _edge(graph, "container:19", "vm:aws", RelationshipType.HOSTED_ON)
    inherit_cloud_provider(graph)
    assert graph.nodes["container:19"].dimensions.cloud_provider == ""


def test_attribute_conflict_on_the_parent_is_not_a_provider() -> None:
    graph = UnifiedGraph(scan_id="attr-conflict", tenant_id="default")
    account = _node("account:x", EntityType.ACCOUNT, "x", "aws")
    account.attributes["cloud_provider"] = "azure"
    graph.add_node(account)
    graph.add_node(_node("bucket:b", EntityType.DATA_STORE, "b"))
    _edge(graph, "account:x", "bucket:b", RelationshipType.CONTAINS)
    inherit_cloud_provider(graph)
    assert graph.nodes["bucket:b"].dimensions.cloud_provider == ""


def test_parents_must_be_provider_scoped_assets() -> None:
    graph = UnifiedGraph(scan_id="parents", tenant_id="default")
    # A provider node HOSTS agents; an AI vendor is not a cloud hosting scope.
    graph.add_node(_node("provider:x", EntityType.PROVIDER, "x", "aws"))
    graph.add_node(_node("container:c", EntityType.CONTAINER, "c"))
    _edge(graph, "provider:x", "container:c", RelationshipType.HOSTS)
    inherit_cloud_provider(graph)
    assert graph.nodes["container:c"].dimensions.cloud_provider == ""


def test_rollup_entries_carry_the_effective_provider() -> None:
    graph = _cloud_graph()
    inherit_cloud_provider(graph)
    top = {row["id"]: row for row in rollup_view(graph)["top_level"]}
    assert top["account:prod"]["cloud_provider"] == "aws"
    assert top["account:prod"]["cloud_provider_basis"] == "declared"
    drilled = drill_down(graph, "account:prod")
    assert drilled["node"]["cloud_provider"] == "aws"
    env_row = next(row for row in drilled["children"] if row["id"] == "env:prod")
    assert env_row["cloud_provider"] == "aws"
    assert env_row["cloud_provider_basis"] == "inherited:contains"
    unscoped = drill_down(graph, "container:ledger")
    assert all(row["cloud_provider"] == "" for row in unscoped["children"])


def test_the_built_graph_stamps_a_pod_from_the_vm_it_is_scheduled_on() -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report

    instance, region = "i-0a1b2c3d4e5f60718", "us-east-1"
    server = {
        "name": "tools/mcp-pod/mcp",
        "url": "http://mcp.tools.svc.cluster.local:8000",
        "transport": "sse",
        "connection_metadata": {
            "k8s_pod_uid": "6f1c2a9e-0d4b-4c55-9a35-3f8e2c1d7b10",
            "k8s_pod": "mcp-pod",
            "k8s_namespace": "tools",
            "k8s_node": "node-a",
            "k8s_node_provider_id": f"aws:///{region}a/{instance}",
        },
    }
    agent = {"name": "kubernetes", "type": "custom", "source": "kubernetes", "mcp_servers": [server]}
    graph = build_unified_graph_from_report({"agents": [agent]})

    pod = graph.nodes["container:k8s:pod:6f1c2a9e-0d4b-4c55-9a35-3f8e2c1d7b10"]
    assert pod.dimensions.cloud_provider == "aws"
    assert pod.attributes["cloud_provider_basis"] == "inherited:hosted_on"
    assert pod.attributes["cloud_provider_source"]["node_id"] == f"cloud_resource:aws:ec2:instance:{instance}"
    # Workloads above the pod keep their own identity; they are not cloud assets.
    servers = [node for node in graph.nodes.values() if node.entity_type.value == "server"]
    assert servers and all("cloud_provider_basis" not in node.attributes for node in servers)


def test_an_inherited_provider_never_becomes_identity_location() -> None:
    from agent_bom.graph.asset_identity import strong_keys
    from agent_bom.graph.correlation_scope import container_occurrence, exact_identity_scope

    graph = _cloud_graph()
    container = graph.nodes["container:checkout"]
    container.attributes.update({"container_id": "abc123", "account_id": "123456789012"})
    before = (container_occurrence(container), strong_keys(container))
    inherit_cloud_provider(graph)
    assert container.dimensions.cloud_provider == "aws"
    # Display and filters see AWS; cross-snapshot identity still sees only what was recorded.
    assert (container_occurrence(container), strong_keys(container)) == before
    assert "cloud_provider" not in exact_identity_scope(container, basis="runtime_stable_id", namespace="x", value="y")
