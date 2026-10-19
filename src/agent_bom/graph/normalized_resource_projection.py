"""Normalized resource projection for unified graph construction."""

from __future__ import annotations

from typing import Any

from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.graph.cloud_context import (
    _add_account_resource_hierarchy,
    _environment_from_tags,
    _recorded_exposure_attributes,
    _resource_environment,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part
from agent_bom.security import sanitize_text


def _add_normalized_cloud_resources(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    account_node_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
) -> None:
    """Promote normalized data / secret / registry / network resources into nodes.

    Covers the resource classes the AWS-shaped loops above do not: secret stores
    (Key Vault), container registries, databases, virtual networks, public IPs,
    and load balancers. Each becomes a ``CLOUD_RESOURCE`` owned by the account so
    it shows up in the environment graph and is reachable by blast-radius. Data
    stores and secret stores carry a data-store keyword in their label so the
    CNAPP/DSPM overlay can attach its companion; resources with a public IP or an
    internet-facing frontend are flagged ``internet_exposed`` for exposure
    analysis. Identity / EXPOSED_TO edges between these and compute/identity nodes
    are added by the overlays once richer relations are available.
    """
    from agent_bom.cloud.resource_model import CloudResourceType, normalize_cloud_inventory

    # normalized type -> (label keyword, graph surface, signals a data store)
    type_meta = {
        CloudResourceType.CONTAINER_CLUSTER: ("kubernetes cluster", "container", False),
        CloudResourceType.SECRET_STORE: ("key vault", "secret-store", True),
        CloudResourceType.CONTAINER_REGISTRY: ("container registry", "registry", False),
        CloudResourceType.DATABASE: ("database", "database", True),
        CloudResourceType.VIRTUAL_NETWORK: ("virtual network", "network", False),
        CloudResourceType.PUBLIC_IP: ("public ip", "network", False),
        CloudResourceType.LOAD_BALANCER: ("load balancer", "network", False),
        CloudResourceType.MESSAGING: ("messaging", "messaging", False),
        CloudResourceType.CACHE: ("redis cache", "cache", False),
        CloudResourceType.BLOCK_STORAGE: ("managed disk", "storage", True),
        CloudResourceType.SERVERLESS_FUNCTION: ("app service", "compute", False),
    }
    pip_node_by_arm_id: dict[str, str] = {}
    load_balancer_nodes: list[tuple[str, dict[str, Any]]] = []
    for res in normalize_cloud_inventory(inventory):
        meta = type_meta.get(res.resource_type)
        if meta is None:
            continue  # storage / compute / identity handled by the dedicated loops
        name = _clean_graph_part(res.name)
        if not name:
            continue
        node_id = cloud_resource_node_id(provider, res.resource_type.value, res.raw or {}, res.account or account_id, region)
        raw = res.raw or {}
        exposure = _recorded_exposure_attributes(raw, "internet_facing")
        if res.resource_type is CloudResourceType.PUBLIC_IP and raw.get("ip_address"):
            exposure["internet_exposed"] = True
            exposure["internet_exposure_evidence"]["public_ip_address"] = sanitize_text(str(raw["ip_address"]))
        if res.resource_type is CloudResourceType.PUBLIC_IP and res.resource_id:
            pip_node_by_arm_id[res.resource_id] = node_id
        if res.resource_type is CloudResourceType.LOAD_BALANCER:
            load_balancer_nodes.append((node_id, raw))
        graph.add_node(_normalized_resource_node(res, node_id, name, meta, provider, account_id, region, data_sources, exposure))
        resource_ids.append(node_id)
        if account_node_id:
            _add_account_resource_hierarchy(
                graph,
                account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
            )

    _wire_public_ip_frontends(graph, load_balancer_nodes, pip_node_by_arm_id)


def _normalized_resource_node(
    res: Any,
    node_id: str,
    name: str,
    meta: tuple[str, str, bool],
    provider: str,
    account_id: str,
    region: str,
    data_sources: list[str],
    exposure: dict[str, Any],
) -> UnifiedNode:
    label_keyword, surface, is_data_store = meta
    resource_tags = dict(res.tags) if getattr(res, "tags", None) else {}
    resource_env = _environment_from_tags(resource_tags) or _resource_environment(res.raw or {})
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.CLOUD_RESOURCE,
        label=f"{label_keyword}: {name}",
        attributes={
            "resource_id": res.resource_id or name,
            "resource_name": name,
            "resource_type": res.resource_type.value,
            "resource_kind": res.native_type,
            "cloud_provider": provider,
            "location": res.region or region,
            **exposure,
            "is_data_store": is_data_store,
            "tags": resource_tags,
            "account_id": account_id,
            "environment": resource_env,
        },
        data_sources=data_sources,
        dimensions=NodeDimensions(cloud_provider=provider, surface=surface, environment=resource_env),
    )


def _wire_public_ip_frontends(
    graph: UnifiedGraph, load_balancer_nodes: list[tuple[str, dict[str, Any]]], pip_node_by_arm_id: dict[str, str]
) -> None:
    # ── Internet exposure path: public IP → load balancer it fronts ──
    # The public IP is the internet entry point; the load balancer (and its
    # backends) sit behind it. EXPOSED_TO from the IP to the LB lets blast-radius
    # and attack-path analysis start at the internet edge.
    for lb_node_id, lb_raw in load_balancer_nodes:
        for pip_arm_id in lb_raw.get("public_ip_ids", []) or []:
            pip_node_id = pip_node_by_arm_id.get(pip_arm_id)
            if pip_node_id:
                graph.add_edge(
                    UnifiedEdge(
                        source=pip_node_id,
                        target=lb_node_id,
                        relationship=RelationshipType.EXPOSED_TO,
                        weight=6.0,
                        evidence={"source": "cloud-inventory", "reason": "public_ip_frontend"},
                    )
                )
