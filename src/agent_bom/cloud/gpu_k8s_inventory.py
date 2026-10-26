"""Collect Kubernetes GPU workloads with read-only ``kubectl get`` and turn them into agents.

Every call is a ``get`` (nodes, pods across namespaces, the GPU Operator
ClusterPolicy) or a local ``config view``; nothing is executed in a pod and
nothing is written to the cluster.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.cloud.gpu_k8s_workloads import (
    GpuStack,
    GpuWorkload,
    cluster_identity,
    cluster_policy_stack,
    gpu_workloads,
    node_contexts,
    stack_packages,
)
from agent_bom.cloud.k8s_gpu_common import container_image_packages
from agent_bom.cloud.normalization import build_cloud_origin
from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface, TransportType

KubectlRunner = Callable[..., Any]


@dataclass
class K8sGpuInventory:
    provider: str = ""
    cluster_key: str = ""
    workloads: list[GpuWorkload] = field(default_factory=list)
    stack: GpuStack = field(default_factory=GpuStack)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "cluster_key": self.cluster_key,
            "workloads": [w.to_dict() for w in self.workloads],
            "stack": {
                "driver_version": self.stack.driver_version,
                "toolkit_version": self.stack.toolkit_version,
                "source": self.stack.source,
            },
        }


def collect_k8s_gpu_inventory(run_kubectl: KubectlRunner, context: str | None = None) -> K8sGpuInventory:
    """Read nodes, pods and the GPU Operator policy; ``run_kubectl`` returns parsed JSON or ``None``."""
    node_list = run_kubectl(["get", "nodes"], context=context)
    if node_list is None:
        return K8sGpuInventory(warnings=["kubectl not available — Kubernetes GPU workload discovery skipped"])
    nodes = node_contexts(node_list)
    provider, cluster_key = cluster_identity(run_kubectl(["config", "view", "--minify"], context=context), nodes)
    inventory = K8sGpuInventory(provider=provider, cluster_key=cluster_key)
    pods = run_kubectl(["get", "pods", "--all-namespaces"], context=context)
    if pods is None:
        inventory.warnings.append("Could not list pods (needs get/list on pods cluster-wide) — GPU workloads not inventoried")
    inventory.workloads = gpu_workloads(pods, nodes, provider=provider, cluster_key=cluster_key)
    inventory.stack = cluster_policy_stack(run_kubectl(["get", "clusterpolicies.nvidia.com"], context=context))
    return inventory


def _workload_packages(workload: GpuWorkload, stack: GpuStack) -> list:
    packages = [pkg for c in workload.containers if c["image"] for pkg in container_image_packages(c["image"])]
    return packages + stack_packages(
        driver_version=workload.driver_version or stack.driver_version,
        toolkit_version=stack.toolkit_version,
        driver_source="gpu-feature-discovery-label" if workload.driver_version else stack.source,
        toolkit_source=stack.source,
    )


def workload_config_path(workload: GpuWorkload) -> str:
    return f"k8s://{workload.cluster_key}/{workload.namespace}/{workload.pod}"


def workload_agent(workload: GpuWorkload, stack: GpuStack) -> Agent:
    """One agent per GPU pod; its packages include the node GPU stack it runs on."""
    ident = f"{workload.namespace}/{workload.pod}"
    server = MCPServer(
        name=f"gpu-workload:{ident}",
        command="",
        transport=TransportType.UNKNOWN,
        surface=ServerSurface.AI_INVENTORY,
        packages=_workload_packages(workload, stack),
        env={name: "" for name in workload.credential_env},
    )
    return Agent(
        name=f"gpu-workload:{ident}",
        agent_type=AgentType.CUSTOM,
        config_path=workload_config_path(workload),
        source="gpu_infra",
        mcp_servers=[server],
        metadata={
            "gpu_workload": workload.to_dict(),
            "cloud_origin": build_cloud_origin(
                provider=workload.provider or "kubernetes",
                service="kubernetes",
                resource_type="gpu-workload",
                resource_id=ident,
                resource_name=workload.pod,
                cluster=workload.cluster_key,
                raw_identity={"namespace": workload.namespace, "pod": workload.pod, "node_pool": workload.pool_name},
            ),
        },
    )
