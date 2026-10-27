"""Agents for GPU infrastructure scan results: GPU containers, the K8s GPU cluster, GPU workloads."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.gpu_k8s_inventory import workload_agent
from agent_bom.cloud.normalization import build_package_purl
from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType
from agent_bom.parsers.gpu_stack import DRIVER


def _gpu_container_agent(c: Any) -> Agent:
    """Build the agent for one GPU container, with CUDA/cuDNN versions as packages."""
    packages: list[Package] = []
    for pkg_name, version in (("cuda-toolkit", c.cuda_version), ("cudnn", c.cudnn_version)):
        if version:
            packages.append(
                Package(
                    name=pkg_name,
                    version=version,
                    ecosystem="container",
                    purl=build_package_purl(ecosystem="container", name=pkg_name, version=version),
                )
            )

    server = MCPServer(name=c.image, command="", transport=TransportType.STDIO, packages=packages)
    cloud_origin = {
        "provider": "gpu",
        "service": "container_runtime",
        "resource_type": c.gpu_vendor or "unknown",
        "resource_id": c.container_id,
        "resource_name": c.name or c.container_id,
        "scope": {
            "image": c.image,
            "gpu_requested": c.gpu_requested,
            "cuda_version": c.cuda_version,
            "cudnn_version": c.cudnn_version,
        },
    }
    return Agent(
        name=c.name or c.container_id,
        agent_type=AgentType.CUSTOM,
        config_path=f"docker://{c.container_id}",
        source="gpu_infra",
        mcp_servers=[server],
        metadata={"cloud_origin": cloud_origin},
    )


def _driver_versions(nodes: list[Any]) -> dict[str, list[str]]:
    versions: dict[str, set[str]] = {}
    for node in nodes:
        if node.cuda_driver_version:
            versions.setdefault(node.gpu_vendor or "unknown", set()).add(node.cuda_driver_version)
    return {vendor: sorted(found) for vendor, found in versions.items()}


def _nvidia_driver_packages(nodes: list[Any]) -> list[Package]:
    """One CPE-identified package per NVIDIA driver release; the NVIDIA CSAF and NVD matchers judge it."""
    nodes_by_version: dict[str, list[str]] = {}
    for node in nodes:
        version = node.cuda_driver_version
        if node.gpu_vendor == "nvidia" and version and DRIVER.cpe(version):
            nodes_by_version.setdefault(version, []).append(node.name)
    return [
        Package(
            name=DRIVER.name,
            version=version,
            ecosystem="generic",
            purl=DRIVER.purl(version),
            cpe=DRIVER.cpe(version),
            is_direct=False,
            resolved_from_registry=False,
            discovery_provenance={
                "source_type": "kubernetes_node_labels",
                "source": "gpu-feature-discovery-label",
                "observed_via": [f"k8s-node:{name}" for name in sorted(names)],
                "confidence": "high",
            },
        )
        for version, names in sorted(nodes_by_version.items())
    ]


def _k8s_gpu_cluster_agent(report: Any) -> Agent:
    """Aggregate the report's K8s GPU nodes into one synthetic cluster agent."""
    total_gpus = sum(n.gpu_capacity for n in report.gpu_nodes)
    vendors = sorted({n.gpu_vendor for n in report.gpu_nodes if n.gpu_vendor})
    node_name = f"k8s-gpu-cluster ({len(report.gpu_nodes)} nodes, {total_gpus} GPUs)"
    node_server = MCPServer(name=node_name, command="", transport=TransportType.STDIO, packages=_nvidia_driver_packages(report.gpu_nodes))
    cloud_origin = {
        "provider": "gpu",
        "service": "kubernetes",
        "resource_type": vendors[0] if len(vendors) == 1 else "mixed" if vendors else "unknown",
        "resource_id": "k8s-gpu-cluster",
        "resource_name": "k8s-gpu-cluster",
        "scope": {
            "node_count": len(report.gpu_nodes),
            "gpu_capacity_total": total_gpus,
            "vendors": vendors,
            "driver_versions": _driver_versions(report.gpu_nodes),
            "firmware_cve_count": len(report.firmware_findings),
        },
    }
    return Agent(
        name="k8s-gpu-cluster",
        agent_type=AgentType.CUSTOM,
        config_path="k8s://gpu-nodes",
        source="gpu_infra",
        mcp_servers=[node_server],
        metadata={"cloud_origin": cloud_origin},
    )


def gpu_infra_to_agents(report: Any) -> list[Agent]:
    """Convert GpuInfraReport to Agent objects for inclusion in AIBOMReport.

    Each GPU container becomes an Agent with its image name as the MCP server.
    K8s GPU nodes appear as a synthetic "k8s-gpu-cluster" agent. Both shapes
    populate ``Agent.metadata["cloud_origin"]`` so the unified-graph builder
    can promote the underlying GPU asset (vendor, runtime, container/node id)
    into ``cloud_resource`` lineage nodes via the existing promoter in
    ``src/agent_bom/graph/builder.py``.
    """
    agents = [_gpu_container_agent(c) for c in report.gpu_containers]

    # Aggregate K8s GPU nodes as a single agent. Lineage promotion happens at
    # the cluster level so dashboards see one cloud_resource per cluster, not
    # one per GPU node — node-level facts live in the scope envelope.
    if report.gpu_nodes:
        agents.append(_k8s_gpu_cluster_agent(report))
    if report.k8s is not None:
        agents.extend(workload_agent(w, report.k8s.stack) for w in report.k8s.workloads)

    return agents
