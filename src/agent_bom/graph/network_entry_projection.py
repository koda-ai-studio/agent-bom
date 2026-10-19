"""Network entry projection for unified graph construction."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.normalization import coerce_truthy
from agent_bom.graph.builder_network_exposure import _add_exposure_path_edge as _add_exposure_path_edge
from agent_bom.graph.builder_network_inventory import NETWORK_INVENTORY_STAGES, _NetworkInventoryContext
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _add_network_edge_inventory(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    account_node_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
    sg_node_by_id: dict[str, str],
    instance_node_by_id: dict[str, str],
) -> None:
    """Promote network-edge inventory into nodes + exposure-relevant edges.

    Emits, from the live inventory payload (all three clouds):

    - **API gateways** (AWS API Gateway, GCP API Gateway/Apigee, Azure API
      Management) → ``API_GATEWAY`` nodes in the API_GATEWAY semantic layer.
    - **WAF / Cloud Armor** web ACLs → ``CLOUD_RESOURCE`` nodes.
    - A ``PROTECTS`` edge from each WAF / API gateway to the resource it fronts,
      so the CNAPP overlay can refine the fronted resource's exposure verdict.
    - **Subnets** → ``CLOUD_RESOURCE``; a public subnet is ``internet_exposed``.
    - **ENIs / NICs** → ``CLOUD_RESOURCE`` wired ``PART_OF`` their instance,
      subnet, and security group(s) so the network path is traversable; an ENI
      carrying a public IP marks its instance internet-reachable and emits
      ``EXPOSED_TO`` the instance.
    - **Elastic/public IPs** → ``EXPOSED_TO`` the attached instance when known.
    - **Internet-facing API gateways** → ``EXPOSED_TO`` protected frontends.
    - NAT/internet gateways, route tables, network ACLs, VPC endpoints, load
      balancers, and IP addresses → ``CLOUD_RESOURCE`` inventory nodes.

    Never raises into the builder; missing/empty collections are a no-op.
    """
    ctx = _NetworkInventoryContext(
        graph=graph,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
        sg_node_by_id=sg_node_by_id,
        instance_node_by_id=instance_node_by_id,
    )
    ctx.index_resource_refs()
    for stage in NETWORK_INVENTORY_STAGES:
        stage(ctx, inventory)
    _wire_network_entry_exposure_paths(
        graph,
        inventory,
        provider=provider,
        subnet_node_by_id=ctx.subnet_node_by_id,
        instance_node_by_id=instance_node_by_id,
    )


def _wire_network_entry_exposure_paths(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    subnet_node_by_id: dict[str, str],
    instance_node_by_id: dict[str, str],
) -> None:
    """Link IGW / public subnet / permissive NACL nodes to reachable instances."""
    public_subnet_ids = {
        sn_id
        for sn in inventory.get("subnets", []) or []
        if isinstance(sn, dict)
        for sn_id in [_clean_graph_part(sn.get("id"))]
        if sn_id and coerce_truthy(sn.get("is_public"))
    }
    igw_by_vpc: dict[str, str] = {}
    for igw in inventory.get("internet_gateways", []) or []:
        if not isinstance(igw, dict):
            continue
        kind = _clean_graph_part(igw.get("kind")) or "internet-gateway"
        if kind != "internet-gateway":
            continue
        ident = _clean_graph_part(igw.get("id"))
        vpc_id = _clean_graph_part(igw.get("vpc_id"))
        if not ident or not vpc_id:
            continue
        node_id = f"cloud_resource:{provider}:network:internet_gateway:{ident}"
        if node_id in graph.nodes:
            graph.nodes[node_id].attributes["internet_exposed"] = True
            igw_by_vpc[vpc_id] = node_id

    _wire_gateway_subnets(graph, inventory, public_subnet_ids, subnet_node_by_id, igw_by_vpc)

    _wire_public_subnet_instances(graph, inventory, public_subnet_ids, subnet_node_by_id, instance_node_by_id)

    _wire_permissive_acls(graph, inventory, public_subnet_ids, subnet_node_by_id, provider, instance_node_by_id)


def _wire_permissive_acls(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    public_subnet_ids: set[str],
    subnet_node_by_id: dict[str, str],
    provider: str,
    instance_node_by_id: dict[str, str],
) -> None:
    for nacl in inventory.get("network_acls", []) or []:
        if not isinstance(nacl, dict) or not coerce_truthy(nacl.get("internet_exposed")):
            continue
        ident = _clean_graph_part(nacl.get("id"))
        if not ident:
            continue
        nacl_node = f"cloud_resource:{provider}:network:network_acl:{ident}"
        if nacl_node not in graph.nodes:
            continue
        for sn_id in nacl.get("subnet_ids", []) or []:
            sn_clean = _clean_graph_part(sn_id)
            # A permissive NACL only implies internet reachability when the
            # subnet is actually public (has an IGW route). A permissive NACL on
            # a private subnet is not internet exposure — skip it to avoid a
            # false EXPOSED_TO edge. Mirrors the IGW branch's public gate above.
            if sn_clean not in public_subnet_ids:
                continue
            sn_node = subnet_node_by_id.get(sn_clean)
            if sn_node:
                _add_exposure_path_edge(
                    graph,
                    source=nacl_node,
                    target=sn_node,
                    reason="permissive_network_acl",
                )
            for instance in inventory.get("instances", []) or []:
                if not isinstance(instance, dict):
                    continue
                if _clean_graph_part(instance.get("subnet_id")) != sn_clean:
                    continue
                inst_node = instance_node_by_id.get(_clean_graph_part(instance.get("instance_id")))
                if inst_node:
                    _add_exposure_path_edge(
                        graph,
                        source=nacl_node,
                        target=inst_node,
                        reason="permissive_network_acl_instance",
                    )


def _wire_public_subnet_instances(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    public_subnet_ids: set[str],
    subnet_node_by_id: dict[str, str],
    instance_node_by_id: dict[str, str],
) -> None:
    for sn_id in public_subnet_ids:
        sn_node = subnet_node_by_id.get(sn_id)
        if not sn_node:
            continue
        for instance in inventory.get("instances", []) or []:
            if not isinstance(instance, dict):
                continue
            if _clean_graph_part(instance.get("subnet_id")) != sn_id:
                continue
            inst_node = instance_node_by_id.get(_clean_graph_part(instance.get("instance_id")))
            if inst_node:
                _add_exposure_path_edge(
                    graph,
                    source=sn_node,
                    target=inst_node,
                    reason="public_subnet_instance",
                )


def _wire_gateway_subnets(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    public_subnet_ids: set[str],
    subnet_node_by_id: dict[str, str],
    igw_by_vpc: dict[str, str],
) -> None:
    for vpc_id, igw_node in igw_by_vpc.items():
        for sn in inventory.get("subnets", []) or []:
            if not isinstance(sn, dict):
                continue
            sn_id = _clean_graph_part(sn.get("id"))
            if sn_id not in public_subnet_ids or _clean_graph_part(sn.get("vpc_id")) != vpc_id:
                continue
            sn_node = subnet_node_by_id.get(sn_id)
            if sn_node:
                _add_exposure_path_edge(
                    graph,
                    source=igw_node,
                    target=sn_node,
                    reason="internet_gateway_public_subnet",
                )
