"""GPU pools, workloads, stack CVEs and posture in the unified graph and the findings stream."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.cloud.gpu_infra import GpuInfraReport, gpu_infra_to_agents
from agent_bom.cloud.gpu_k8s_inventory import collect_k8s_gpu_inventory
from agent_bom.cloud.gpu_node_pools import gpu_pool_node_id
from agent_bom.cloud.gpu_posture import attach_gpu_posture_findings
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.gpu_paths import gpu_host_escape_paths
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.models import AIBOMReport, BlastRadius, Severity, Vulnerability
from agent_bom.output.json_fmt import to_json
from tests._sdk_stub_helpers import patch_sdk_namespace
from tests.test_gpu_k8s_workloads import EKS_ARN, recorded_kubectl
from tests.test_gpu_node_pools import _aks_module, _EksClient, _gke_module, _load, _Session

NODE_ROLE = "arn:aws:iam::111122223333:role/ml-prod-gpu-node"


def _eks_inventory() -> dict[str, Any]:
    from agent_bom.cloud.aws_inv.services import _discover_eks

    clusters = _discover_eks(
        _Session(_EksClient(_load("eks_describe_nodegroups.json"))), "us-east-1", account_id="111122223333", warnings=[]
    )
    role = {"principal_type": "iam-role", "name": "ml-prod-gpu-node", "arn": NODE_ROLE, "policies": [], "trust_principals": []}
    return {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "eks_clusters": clusters,
        "roles": [role],
    }


def _gke_inventory() -> dict[str, Any]:
    from agent_bom.cloud.gcp_inv.compute_storage import _discover_gke_clusters

    with patch_sdk_namespace(_gke_module(_load("gke_clusters.json")), "google"):
        clusters = _discover_gke_clusters("example-ml-project", credentials=None, warnings=[])
    return {
        "provider": "gcp",
        "status": "ok",
        "account_id": "example-ml-project",
        "project_id": "example-ml-project",
        "gke_clusters": clusters,
    }


def _aks_inventory() -> dict[str, Any]:
    from agent_bom.cloud.azure_inv.compute_storage import _discover_aks_clusters

    subscription = "00000000-0000-0000-0000-000000000000"
    with patch_sdk_namespace(_aks_module(_load("aks_managed_clusters.json")), "azure"):
        clusters = _discover_aks_clusters(None, subscription, warnings=[])
    return {
        "provider": "azure",
        "status": "ok",
        "subscription_id": subscription,
        "account_id": subscription,
        "container_clusters": clusters,
    }


def _gpu_pool_nodes(graph: UnifiedGraph) -> list[Any]:
    return [n for n in graph.nodes.values() if n.attributes.get("resource_type") == "gpu_node_pool"]


def _contained_by_cluster(graph: UnifiedGraph, node_id: str) -> bool:
    return any(
        e.relationship == RelationshipType.CONTAINS and graph.nodes[e.source].attributes.get("resource_type") == "container_cluster"
        for e in graph.reverse_adjacency.get(node_id, [])
        if e.source in graph.nodes
    )


@pytest.mark.parametrize(
    ("inventory", "expected_pools"),
    [(_eks_inventory, {"gpu-a10g", "train-custom"}), (_gke_inventory, {"l4-shared", "a100-mig"}), (_aks_inventory, {"gpunc", "gput4"})],
)
def test_every_inventoried_gpu_pool_hangs_off_its_cluster(inventory: Any, expected_pools: set[str]) -> None:
    graph = build_unified_graph_from_report({"cloud_inventory": [inventory()]})
    pools = _gpu_pool_nodes(graph)
    assert {p.attributes["resource_name"] for p in pools} == expected_pools  # non-GPU pools stay off the graph
    for pool in pools:
        assert _contained_by_cluster(graph, pool.id), f"{pool.id} is not contained by its cluster node"
        assert pool.attributes["gpu"] is True and pool.attributes["accelerator_type"]


def test_eks_gpu_pool_assumes_its_node_role_and_carries_capacity() -> None:
    graph = build_unified_graph_from_report({"cloud_inventory": [_eks_inventory()]})
    pool = graph.nodes[gpu_pool_node_id("aws", EKS_ARN, "gpu-a10g")]
    assert (pool.attributes["accelerator_type"], pool.attributes["max_nodes"]) == ("A10G", 6)
    assert pool.attributes["gpu_driver"]["management"] == "provider-managed"
    role_edges = [e for e in graph.adjacency[pool.id] if e.relationship == RelationshipType.ASSUMES]
    assert [graph.nodes[e.target].entity_type for e in role_edges] == [EntityType.ROLE]


def _workload_report(*, with_inventory: bool) -> AIBOMReport:
    inv = collect_k8s_gpu_inventory(recorded_kubectl())
    gpu = GpuInfraReport(gpu_containers=[], dcgm_endpoints=[], gpu_nodes=[], warnings=[], k8s=inv)
    agents = gpu_infra_to_agents(gpu)
    llm = next(a for a in agents if a.name == "gpu-workload:ml/llm-inference-7d9f")
    server = llm.mcp_servers[0]
    toolkit = next(p for p in server.packages if p.name == "nvidia-container-toolkit")
    vuln = Vulnerability(
        id="CVE-2024-0132", summary="Container Toolkit TOCTOU container escape", severity=Severity.CRITICAL, cvss_score=9.0
    )
    toolkit.vulnerabilities = [vuln]
    blast = BlastRadius(
        vulnerability=vuln,
        package=toolkit,
        affected_servers=[server],
        affected_agents=[llm],
        exposed_credentials=["HF_TOKEN"],
        exposed_tools=[],
    )
    blast.calculate_risk_score()
    report = AIBOMReport(
        agents=agents,
        blast_radii=[blast],
        gpu_infra_data=gpu.report_data,
        cloud_inventory_data=[_eks_inventory()] if with_inventory else None,
    )
    attach_gpu_posture_findings(report)
    return report


@pytest.fixture(scope="module")
def workload_graph() -> UnifiedGraph:
    return build_unified_graph_from_report(to_json(_workload_report(with_inventory=True)))


def _agent(graph: UnifiedGraph, name: str) -> Any:
    (agent,) = [n for n in graph.nodes.values() if n.entity_type == EntityType.AGENT and n.label == name]
    return agent


def test_workload_runs_on_the_same_pool_node_the_cloud_inventory_created(workload_graph: UnifiedGraph) -> None:
    agent = _agent(workload_graph, "gpu-workload:ml/llm-inference-7d9f")
    (pool_id,) = [
        e.target for e in workload_graph.adjacency[agent.id] if e.relationship == RelationshipType.HOSTED_ON and "gpu_node_pool" in e.target
    ]
    assert pool_id == gpu_pool_node_id("aws", EKS_ARN, "gpu-a10g")
    attrs = workload_graph.nodes[pool_id].attributes
    assert attrs["pool_id"].startswith("arn:aws:eks:")  # from the EKS API
    assert attrs["observed_driver_version"] == "535.104.05"  # from GPU Feature Discovery on the node
    assert _contained_by_cluster(workload_graph, pool_id)


def test_workload_identity_chain_reaches_the_irsa_role(workload_graph: UnifiedGraph) -> None:
    agent = _agent(workload_graph, "gpu-workload:ml/llm-inference-7d9f")
    (sa,) = [e.target for e in workload_graph.adjacency[agent.id] if e.relationship == RelationshipType.AUTHENTICATES_AS]
    assert workload_graph.nodes[sa].entity_type == EntityType.SERVICE_ACCOUNT
    (role,) = [e.target for e in workload_graph.adjacency[sa] if e.relationship == RelationshipType.ASSUMES]
    assert workload_graph.nodes[role].attributes["arn"] == "arn:aws:iam::111122223333:role/llm-model-reader"


def test_container_toolkit_cve_path_runs_through_the_workload_to_its_identities(workload_graph: UnifiedGraph) -> None:
    paths = gpu_host_escape_paths(workload_graph)
    llm = _agent(workload_graph, "gpu-workload:ml/llm-inference-7d9f").id
    chains = {tuple(workload_graph.nodes[h].entity_type for h in p.hops): p for p in paths if p.source == llm}
    identity = chains[(EntityType.AGENT, EntityType.SERVICE_ACCOUNT, EntityType.ROLE)]
    assert identity.vuln_ids == ["CVE-2024-0132"] and identity.reachability == "unknown"
    node_escape = chains[(EntityType.AGENT, EntityType.CLOUD_RESOURCE, EntityType.ROLE)]
    assert workload_graph.nodes[node_escape.hops[-1]].attributes.get("arn", node_escape.hops[-1]).endswith("ml-prod-gpu-node")
    served = {(p.source, tuple(p.hops)) for p in _derived_attack_paths(workload_graph)}
    assert (identity.source, tuple(identity.hops)) in served  # the API / MCP path list carries it


def test_paths_need_a_vulnerable_host_stack_package() -> None:
    report = _workload_report(with_inventory=True)
    for agent in report.agents:
        for pkg in agent.mcp_servers[0].packages:
            pkg.vulnerabilities = []
    report.blast_radii = []
    assert gpu_host_escape_paths(build_unified_graph_from_report(to_json(report))) == []


def test_gpu_posture_is_one_finding_stream_bound_to_graph_assets(workload_graph: UnifiedGraph) -> None:
    findings = [f for f in _workload_report(with_inventory=True).to_findings() if f.evidence.get("category") == "gpu_posture"]
    checks = {(f.evidence["check_id"], f.asset.name) for f in findings}
    assert ("GPU-010", "research/notebook-0") in checks
    assert ("GPU-011", "research/notebook-0") in checks
    assert ("GPU-012", "research/notebook-0") in checks
    assert ("GPU-013", "gpu-a10g") in checks  # ml + research share a time-sliced pool
    assert ("GPU-001", "ml-prod/gpu-a10g") in checks  # SSH open to the internet on the node group
    assert ("GPU-004", "ml-prod/gpu-a10g") in checks  # EKS does not auto-taint GPU pools
    assert ("GPU-005", "ml-prod/train-custom") in checks  # CUSTOM AMI driver
    assert not any(c == "GPU-003" for c, _ in checks)  # GKE-only check never fires on AWS
    finding_ids = {f.id for f in findings}
    nodes = {n.attributes.get("finding_id"): n for n in workload_graph.nodes.values() if n.entity_type == EntityType.MISCONFIGURATION}
    assert finding_ids <= set(nodes), "every GPU posture finding has a graph node"
    for fid in finding_ids:
        holders = [e.source for e in workload_graph.reverse_adjacency[nodes[fid].id] if e.relationship == RelationshipType.VULNERABLE_TO]
        assert holders, f"GPU finding {fid} is not attached to an asset"
