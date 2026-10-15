"""HOSTED_ON: a workload's CVE path runs through the host it runs on."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.hosting_projection import provider_id_host
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.relationship_specs import TraversalClass, relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType

ACCOUNT = "210987654321"
REGION = "us-east-1"
INSTANCE = "i-0a1b2c3d4e5f60718"
ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{INSTANCE}"
VM = f"cloud_resource:aws:aws_instance:{ACCOUNT}/{REGION}/{INSTANCE}"
POD_UID = "6f1c2a9e-0d4b-4c55-9a35-3f8e2c1d7b10"


def _inventory() -> dict:
    return {
        "status": "ok",
        "provider": "aws",
        "account_id": ACCOUNT,
        "region": REGION,
        "instances": [{"instance_id": INSTANCE, "name": "node-a", "region": REGION}],
    }


def _vm_cve() -> dict:
    return {
        "id": "inspector-1",
        "finding_type": "CVE",
        "cve_id": "CVE-2024-1111",
        "source": "CLOUD_SECURITY",
        "severity": "high",
        "title": "openssl out-of-bounds read",
        "asset": {"name": "node-a", "asset_type": "cloud_resource", "identifier": ARN, "provider": "aws"},
    }


def _k8s_agent() -> dict:
    return {
        "name": "kubernetes",
        "type": "custom",
        "source": "kubernetes",
        "mcp_servers": [
            {
                "name": "tools/mcp-pod/mcp",
                "url": "http://mcp.tools.svc.cluster.local:8000",
                "transport": "sse",
                "connection_metadata": {
                    "k8s_pod_uid": POD_UID,
                    "k8s_pod": "mcp-pod",
                    "k8s_namespace": "tools",
                    "k8s_node": "node-a",
                    "k8s_node_provider_id": f"aws:///{REGION}a/{INSTANCE}",
                },
            }
        ],
    }


def test_hosted_on_is_a_dependency_from_workloads_to_hosts() -> None:
    spec = relationship_spec(RelationshipType.HOSTED_ON)
    assert spec is not None and spec.traversal_class is TraversalClass.DEPENDENCY
    assert spec.allows(EntityType.SERVER, EntityType.CONTAINER)
    assert spec.allows(EntityType.CONTAINER, EntityType.CLOUD_RESOURCE)
    assert not spec.allows(EntityType.CLOUD_RESOURCE, EntityType.AGENT)


def test_agent_to_pod_to_vm_to_cve_path_exists() -> None:
    graph = build_unified_graph_from_report({"agents": [_k8s_agent()], "cloud_inventory": _inventory(), "findings": [_vm_cve()]})

    pod = f"container:k8s:pod:{POD_UID}"
    assert graph.nodes[pod].attributes["kubernetes_uid"] == POD_UID
    assert {(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.HOSTED_ON} >= {(pod, VM)}
    hops = [path.hops for path in _derived_attack_paths(graph) if path.target == "vuln:CVE-2024-1111"]
    assert any(hop[:1] == ["agent:kubernetes"] and pod in hop and hop[-2:] == [VM, "vuln:CVE-2024-1111"] for hop in hops)
    assert any("hosted_on" in path.edges for path in _derived_attack_paths(graph))


def test_vm_cve_with_nothing_hosted_gets_a_standalone_path() -> None:
    graph = build_unified_graph_from_report({"cloud_inventory": _inventory(), "findings": [_vm_cve()]})

    hops = [path.hops for path in _derived_attack_paths(graph) if path.target == "vuln:CVE-2024-1111"]
    assert [VM, "vuln:CVE-2024-1111"] in hops


def test_cloud_origin_agent_is_hosted_on_its_resource_and_account_rollup_is_unchanged() -> None:
    agent = {
        "name": "support-bot",
        "type": "custom",
        "source": "aws-bedrock",
        "mcp_servers": [],
        "metadata": {
            "cloud_origin": {
                "provider": "aws",
                "service": "bedrock",
                "resource_type": "agent",
                "resource_id": "AGENT123",
                "scope": {"account_id": ACCOUNT},
            }
        },
    }
    graph = build_unified_graph_from_report({"agents": [agent]})

    resource = "cloud_resource:aws:bedrock:agent:AGENT123"
    assert graph.has_edge("agent:support-bot", resource)
    assert any(e.relationship == RelationshipType.HOSTED_ON for e in graph.edges_from("agent:support-bot"))
    assert not [e for e in graph.edges_from(resource) if e.relationship == RelationshipType.HOSTS and e.target == "agent:support-bot"]
    account = f"account:aws:{ACCOUNT}"
    assert any(e.relationship == RelationshipType.HOSTS and e.target == resource for e in graph.edges_from(account))


def test_provider_ids_name_the_inventory_host() -> None:
    aws = provider_id_host(f"aws:///{REGION}a/{INSTANCE}")
    assert aws is not None and aws.id == f"cloud_resource:aws:ec2:instance:{INSTANCE}" and aws.attributes["region"] == REGION
    gce = provider_id_host("gce://demo-project/us-central1-a/node-1")
    assert gce is not None and gce.attributes["self_link"] == "projects/demo-project/zones/us-central1-a/instances/node-1"
    assert provider_id_host("kind://docker/kind/kind-control-plane") is None


def test_discovery_records_pod_uid_node_and_provider_id() -> None:
    from agent_bom.discovery.k8s_hosting import node_provider_ids, pod_hosting_metadata

    def kubectl(*args: str) -> dict:
        assert args == ("get", "nodes", "-o", "json")
        return {
            "items": [{"metadata": {"name": "node-a"}, "spec": {"providerID": f"aws:///{REGION}a/{INSTANCE}"}}, {"metadata": {"name": "x"}}]
        }

    pod = {"metadata": {"uid": POD_UID, "name": "mcp-pod", "namespace": "tools"}, "spec": {"nodeName": "node-a"}}
    metadata = pod_hosting_metadata(pod, cluster="prod", provider_ids=node_provider_ids(kubectl))

    assert metadata == {
        "k8s_pod_uid": POD_UID,
        "k8s_pod": "mcp-pod",
        "k8s_namespace": "tools",
        "k8s_cluster": "prod",
        "k8s_node": "node-a",
        "k8s_node_provider_id": f"aws:///{REGION}a/{INSTANCE}",
    }


def test_demo_compute_lane_meets_its_identity_and_hosting_contract() -> None:
    from collections import Counter

    from agent_bom.demo_estate.compute_identity_lane import DEMO_COMPUTE_VMS, DEMO_HOSTNAME_DECOYS, compute_lane_report
    from agent_bom.graph.asset_identity import family_of, strong_keys

    graph = build_unified_graph_from_report(compute_lane_report())
    status = graph.analysis_status["asset_canonicalization"].observed
    keys = Counter((family_of(node), key.text) for node in graph.nodes.values() if family_of(node) for key in strong_keys(node))
    paths = _derived_attack_paths(graph)

    assert status["merged_groups"] == DEMO_COMPUTE_VMS and status["conflicts"] == 0
    assert status["candidate_edges"] == DEMO_HOSTNAME_DECOYS
    assert not [key for key, count in keys.items() if count > 1]
    assert any("hosted_on" in path.edges for path in paths)
    vms_with_cves = {
        e.source
        for e in graph.edges
        if e.relationship == RelationshipType.VULNERABLE_TO
        and graph.nodes[e.target].entity_type == EntityType.VULNERABILITY
        and graph.nodes[e.source].entity_type == EntityType.CLOUD_RESOURCE
    }
    assert vms_with_cves and vms_with_cves <= {hop for path in paths for hop in path.hops}
