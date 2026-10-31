"""Project GPU node pools, GPU workloads and GPU posture into the unified graph.

- A managed Kubernetes GPU pool (EKS node group, GKE node pool, AKS agent pool)
  becomes a ``CLOUD_RESOURCE`` (``resource_type=gpu_node_pool``) that its
  cluster ``CONTAINS``; the pool ``ASSUMES`` its node IAM role / service
  account when that identity is in the graph.
- GPU instances (EC2, GCE, Azure VMs) keep their node and gain ``gpu_*``
  attributes.
- A Kubernetes GPU workload agent is ``HOSTED_ON`` its pool, ``AUTHENTICATES_AS``
  its Kubernetes service account, which ``ASSUMES`` the IRSA role it was
  given. The workload's packages carry the node driver / Container Toolkit, so
  a toolkit CVE reaches the workload, its service account and the role.
- Snowflake SPCS GPU compute pools are owned by their account.

GPU posture findings reach the graph through the report finding rows: each
names its pool node id (or its workload agent's stable id) as the asset.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.cloud.gpu_accelerators import aws_instance_accelerator, azure_vm_accelerator, gcp_machine_accelerator
from agent_bom.cloud.gpu_node_pools import gpu_pool_node_id
from agent_bom.cloud.gpu_posture import CLUSTER_COLLECTIONS, spcs_pool_node_id
from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.cloud_context import _normalize_cloud_inventory
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.identity_nodes import identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part

if TYPE_CHECKING:
    from agent_bom.cloud.gpu_k8s_workloads import GpuWorkload

_SERVICE = {"aws": "eks", "gcp": "gke", "azure": "aks"}
_CLUSTER_KIND = {"aws": "eks:container_cluster", "gcp": "gke:container_cluster", "azure": "container_cluster"}
_INSTANCE_CLASSIFIERS = {"aws": aws_instance_accelerator, "gcp": gcp_machine_accelerator, "azure": azure_vm_accelerator}
_POOL_ATTRS = (
    "pool_id",
    "pool_kind",
    "cluster_name",
    "machine_types",
    "gpu_vendor",
    "accelerator_type",
    "accelerators_per_node",
    "min_nodes",
    "max_nodes",
    "node_count",
    "gpu_driver",
    "gpu_sharing",
    "node_identity",
    "image",
    "node_public_ip",
    "ssh_open_to_internet",
)


def _sources(data_source: str, extra: str) -> list[str]:
    return sorted({data_source, extra} - {""})


def _pool_node(node_id: str, pool: dict[str, Any], provider: str, account_id: str, data_sources: list[str]) -> UnifiedNode:
    name = str(pool.get("name") or "")
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.CLOUD_RESOURCE,
        label=f"gpu node pool: {pool.get('cluster_name') or ''}/{name}".replace(": /", ": "),
        attributes={
            "resource_id": str(pool.get("pool_id") or name),
            "resource_name": name,
            "resource_type": "gpu_node_pool",
            "resource_kind": str(pool.get("pool_kind") or "gpu-node-pool"),
            "cloud_provider": provider,
            "cloud_service": _SERVICE.get(provider, "kubernetes"),
            "account_id": account_id,
            "gpu": True,
            **{key: pool[key] for key in _POOL_ATTRS if key in pool},
            "taint_count": len(pool.get("taints") or []),
        },
        data_sources=data_sources,
        dimensions=NodeDimensions(cloud_provider=provider, surface="compute"),
    )


def _link_pool_identity(graph: UnifiedGraph, pool_node_id: str, provider: str, identity: str) -> None:
    candidates = {
        "aws": [identity_node_id(EntityType.ROLE, "aws", identity)],
        "gcp": [identity_node_id(EntityType.SERVICE_ACCOUNT, "gcp", identity)],
    }.get(provider, [])
    for candidate in candidates:
        if identity and candidate in graph.nodes:
            _add_rel_edge(
                graph, pool_node_id, candidate, RelationshipType.ASSUMES, {"source": "cloud-inventory", "reason": "node_identity"}
            )


def _project_cloud_pools(graph: UnifiedGraph, cloud_inventory: Any, data_source: str) -> None:
    for raw_inventory in cloud_inventory if isinstance(cloud_inventory, list) else [cloud_inventory]:
        if not isinstance(raw_inventory, dict) or raw_inventory.get("status") not in ("ok", "partial"):
            continue
        inventory = _normalize_cloud_inventory(raw_inventory)
        provider = clean_graph_part(inventory.get("provider")) or "aws"
        account_id = clean_graph_part(inventory.get("account_id"))
        region = clean_graph_part(inventory.get("region"))
        scope_account = clean_graph_part(inventory.get("subscription_id")) or account_id if provider == "azure" else account_id
        sources = _sources(data_source, f"cloud:{provider}")
        for cluster in inventory.get(CLUSTER_COLLECTIONS.get(provider, ""), []) or []:
            if not isinstance(cluster, dict):
                continue
            cluster_node_id = cloud_resource_node_id(provider, _CLUSTER_KIND[provider], cluster, scope_account, region)
            for pool in cluster.get("node_pools") or []:
                if not isinstance(pool, dict) or not pool.get("gpu"):
                    continue
                pool_node_id = gpu_pool_node_id(provider, str(pool.get("cluster_key") or ""), str(pool.get("name") or ""))
                graph.add_node(_pool_node(pool_node_id, pool, provider, account_id, sources))
                if cluster_node_id in graph.nodes:
                    _add_rel_edge(
                        graph, cluster_node_id, pool_node_id, RelationshipType.CONTAINS, {"source": "cloud-inventory", "via": "node_pool"}
                    )
                    graph.nodes[cluster_node_id].attributes["gpu_node_pool_count"] = (
                        int(graph.nodes[cluster_node_id].attributes.get("gpu_node_pool_count") or 0) + 1
                    )
                _link_pool_identity(graph, pool_node_id, provider, str(pool.get("node_identity") or ""))


def _annotate_gpu_instances(graph: UnifiedGraph) -> None:
    for node in graph.nodes.values():
        attrs = node.attributes
        if node.entity_type != EntityType.CLOUD_RESOURCE or not attrs.get("instance_type"):
            continue
        classify = _INSTANCE_CLASSIFIERS.get(str(attrs.get("cloud_provider") or ""))
        acc = classify(str(attrs["instance_type"])) if classify else None
        if acc is not None:
            attrs.update(gpu=True, gpu_vendor=acc.vendor, accelerator_type=acc.model, accelerators_per_node=acc.count)


def _ensure_k8s_pool(graph: UnifiedGraph, workload: GpuWorkload, sources: list[str]) -> str:
    pool_node_id = gpu_pool_node_id(workload.provider, workload.cluster_key, workload.pool_name)
    if pool_node_id not in graph.nodes:
        pool = {
            "name": workload.pool_name,
            "pool_kind": "kubernetes-gpu-nodes",
            "cluster_name": workload.cluster_key,
            "gpu_sharing": workload.gpu_sharing,
        }
        graph.add_node(_pool_node(pool_node_id, pool, workload.provider, "", sources))
    attrs = graph.nodes[pool_node_id].attributes
    if workload.driver_version:
        attrs["observed_driver_version"] = workload.driver_version
    if workload.gpu_sharing:
        attrs.setdefault("observed_gpu_sharing", workload.gpu_sharing)
    return pool_node_id


def _service_account_node(graph: UnifiedGraph, workload: GpuWorkload, sources: list[str]) -> str:
    sa_id = f"{workload.cluster_key}/{workload.namespace}/{workload.service_account}"
    node_id = identity_node_id(EntityType.SERVICE_ACCOUNT, "kubernetes", sa_id)
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.SERVICE_ACCOUNT,
            label=f"k8s service account: {workload.namespace}/{workload.service_account}",
            attributes={
                "principal_type": "kubernetes-service-account",
                "namespace": workload.namespace,
                "cluster_key": workload.cluster_key,
            },
            data_sources=sources,
            dimensions=NodeDimensions(cloud_provider=workload.provider, surface="identity"),
        )
    )
    return node_id


def _irsa_role(graph: UnifiedGraph, role_arn: str, sources: list[str]) -> str:
    node_id = identity_node_id(EntityType.ROLE, "aws", role_arn)
    if node_id not in graph.nodes:
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.ROLE,
                label=role_arn.rsplit("/", 1)[-1],
                attributes={"arn": role_arn, "cloud_provider": "aws", "source": "eks-pod-identity-webhook"},
                data_sources=sources,
                dimensions=NodeDimensions(cloud_provider="aws", surface="identity"),
            )
        )
    return node_id


def _workload_from(raw: dict[str, Any]) -> GpuWorkload:
    # cloud.gpu_k8s_workloads reaches parsers; keep it off the graph schema import path.
    from agent_bom.cloud.gpu_k8s_workloads import GpuWorkload

    fields = {key: raw[key] for key in GpuWorkload.__dataclass_fields__ if key in raw}
    return GpuWorkload(**fields)


def _workload_agent_id(graph: UnifiedGraph, indexes: BuildIndexes, workload: GpuWorkload) -> str:
    """The agent node for a workload: same name, and the same cluster in its cloud origin."""
    for agent_id in indexes.agent_name_to_ids.get(f"gpu-workload:{workload.namespace}/{workload.pod}", []):
        origin = (graph.nodes[agent_id].attributes.get("cloud_origin") or {}) if agent_id in graph.nodes else {}
        if (origin.get("scope") or {}).get("cluster") == workload.cluster_key:
            return agent_id
    return ""


def _project_k8s_workloads(graph: UnifiedGraph, gpu_infra: Any, indexes: BuildIndexes, data_source: str) -> None:
    """Wire each workload agent to its pool, service account and IRSA role."""
    k8s = (gpu_infra or {}).get("k8s") if isinstance(gpu_infra, dict) else None
    sources = _sources(data_source, "gpu_infra")
    for raw in (k8s or {}).get("workloads") or []:
        workload = _workload_from(raw)
        agent_id = _workload_agent_id(graph, indexes, workload)
        if not agent_id:
            continue
        if workload.pool_name:
            pool_id = _ensure_k8s_pool(graph, workload, sources)
            _add_rel_edge(graph, agent_id, pool_id, RelationshipType.HOSTED_ON, {"source": "kubernetes", "via": "node_pool"})
        sa_node = _service_account_node(graph, workload, sources)
        _add_rel_edge(graph, agent_id, sa_node, RelationshipType.AUTHENTICATES_AS, {"source": "kubernetes", "via": "serviceAccountName"})
        if workload.aws_role_arn:
            role_node = _irsa_role(graph, workload.aws_role_arn, sources)
            _add_rel_edge(graph, sa_node, role_node, RelationshipType.ASSUMES, {"source": "kubernetes", "via": "AWS_ROLE_ARN"})


def _project_spcs_pools(graph: UnifiedGraph, services: Any, data_source: str) -> None:
    if not isinstance(services, dict) or services.get("status") != "ok":
        return
    account = clean_graph_part(services.get("account"))
    sources = _sources(data_source, "snowflake-services")
    account_node = identity_node_id(EntityType.ACCOUNT, "snowflake", account) if account else ""
    for pool in services.get("compute_pools") or []:
        if not isinstance(pool, dict) or not pool.get("name"):
            continue
        node_id = spcs_pool_node_id(account, str(pool["name"]))
        node = _pool_node(node_id, pool, "snowflake", account, sources)
        node.label = f"compute pool: {pool['name']}"
        node.attributes.update(
            resource_type="compute_pool", cloud_service="spcs", gpu=bool(pool.get("gpu")), instance_family=pool.get("instance_family")
        )
        graph.add_node(node)
        if account_node in graph.nodes:
            _add_rel_edge(graph, account_node, node_id, RelationshipType.CONTAINS, {"source": "snowflake-services"})


def project_gpu_compute(graph: UnifiedGraph, report: dict[str, Any], indexes: BuildIndexes, data_source: str) -> None:
    """Project every GPU surface in a JSON-shaped report; absent sections are no-ops."""
    _project_cloud_pools(graph, report.get("cloud_inventory"), data_source)
    _annotate_gpu_instances(graph)
    _project_k8s_workloads(graph, report.get("gpu_infra"), indexes, data_source)
    _project_spcs_pools(graph, report.get("snowflake_services"), data_source)
