"""Network-edge inventory stages for the unified graph builder.

Each stage promotes one inventory collection (subnets, edge resources, IP
addresses, ENIs/NICs, WAF web ACLs, API gateways) into graph nodes and the
exposure-relevant edges between them. Stages share one ``_NetworkInventoryContext``
so resource emission, account hierarchy and ``PROTECTS`` wiring stay uniform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bom.cloud.normalization import coerce_bool_or_none
from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.graph.builder_network_edges import _GCP_LB_COLLECTION, _NETWORK_EDGE_COLLECTIONS
from agent_bom.graph.builder_network_exposure import _add_exposure_path_edge
from agent_bom.graph.cloud_context import _add_account_resource_hierarchy, _recorded_exposure_attributes
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


@dataclass
class _NetworkInventoryContext:
    graph: UnifiedGraph
    provider: str
    account_id: str
    account_node_id: str
    region: str
    data_sources: list[str]
    resource_ids: list[str]
    sg_node_by_id: dict[str, str]
    instance_node_by_id: dict[str, str]
    ref_to_node: dict[str, str] = field(default_factory=dict)
    subnet_node_by_id: dict[str, str] = field(default_factory=dict)

    def node_id(self, kind: str, record: dict[str, Any], native: str) -> str:
        return cloud_resource_node_id(self.provider, kind, {**record, "id": native}, self.account_id, self.region)

    def index_resource_refs(self) -> None:
        # Provider identifiers are bindings. Display names are not identity.
        for nid in self.resource_ids:
            node = self.graph.nodes.get(nid)
            if node is None:
                continue
            # The canonical resource key distinguishes name-only fallbacks.
            if ":scoped/" in node.id and "/name/" in node.id:
                continue
            for key in ("resource_id",):
                ref = _clean_graph_part(node.attributes.get(key))
                if ref:
                    previous = self.ref_to_node.get(ref, nid)
                    self.ref_to_node[ref] = nid if previous == nid else ""

    def link_account(self, node_id: str) -> None:
        self.resource_ids.append(node_id)
        if self.account_node_id:
            _add_account_resource_hierarchy(
                self.graph,
                self.account_node_id,
                node_id,
                evidence={"source": "cloud-inventory"},
            )

    def emit_resource(self, *, node_id: str, service: str, rtype: str, kind: str, label: str, name: str, attrs: dict[str, Any]) -> None:
        self.graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{label}: {name}",
                attributes={
                    "resource_name": name,
                    "resource_type": rtype,
                    "resource_kind": kind,
                    "cloud_provider": self.provider,
                    "cloud_service": service,
                    "location": _clean_graph_part(attrs.get("location")) or self.region,
                    "account_id": self.account_id,
                    **attrs,
                },
                data_sources=self.data_sources,
                dimensions=NodeDimensions(cloud_provider=self.provider, surface="network"),
            )
        )
        self.link_account(node_id)

    def protect(self, source_node_id: str, targets: list[Any], reason: str) -> None:
        for target_ref in targets or []:
            ref = _clean_graph_part(target_ref)
            target_node_id = self.ref_to_node.get(ref)
            if not target_node_id:
                continue
            self.graph.add_edge(
                UnifiedEdge(
                    source=source_node_id,
                    target=target_node_id,
                    relationship=RelationshipType.PROTECTS,
                    traversable=False,
                    weight=4.0,
                    evidence={"source": "cloud-inventory", "reason": reason},
                )
            )

    def expose_targets(self, source_node_id: str, targets: list[Any], reason: str) -> None:
        for target_ref in targets or []:
            ref = _clean_graph_part(target_ref)
            target_node_id = self.ref_to_node.get(ref)
            if target_node_id:
                _add_exposure_path_edge(self.graph, source=source_node_id, target=target_node_id, reason=reason)

    def part_of(self, source: str, target: str) -> None:
        self.graph.add_edge(
            UnifiedEdge(source=source, target=target, relationship=RelationshipType.PART_OF, evidence={"source": "cloud-inventory"})
        )


def _dict_items(inventory: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [item for item in inventory.get(key, []) or [] if isinstance(item, dict)]


def _add_subnets(ctx: _NetworkInventoryContext, inventory: dict[str, Any]) -> None:
    """Subnets with recorded route classification, not effective reachability."""
    for sn in _dict_items(inventory, "subnets"):
        sn_id = _clean_graph_part(sn.get("id"))
        if not sn_id:
            continue
        node_id = ctx.node_id("network:subnet", sn, sn_id)
        ctx.subnet_node_by_id[sn_id] = node_id
        ctx.emit_resource(
            node_id=node_id,
            service="network",
            rtype="subnet",
            kind="subnet",
            label="subnet",
            name=_clean_graph_part(sn.get("name")) or sn_id,
            attrs={
                "resource_id": sn_id,
                "location": _clean_graph_part(sn.get("location")) or ctx.region,
                "vpc_id": _clean_graph_part(sn.get("vpc_id")),
                "cidr": _clean_graph_part(sn.get("cidr")),
                "is_public": coerce_bool_or_none(sn.get("is_public")),
                **_recorded_exposure_attributes(sn, "is_public"),
            },
        )


def _add_edge_resources(ctx: _NetworkInventoryContext, inventory: dict[str, Any]) -> None:
    """Generic edge resources (NAT/IGW/route-table/NACL/VPCe + GCP LB)."""
    collections = list(_NETWORK_EDGE_COLLECTIONS)
    if ctx.provider == "gcp":
        collections.append(_GCP_LB_COLLECTION)
    for coll_key, svc, rtype, kind, label, id_field in collections:
        for item in _dict_items(inventory, coll_key):
            ident = _clean_graph_part(item.get(id_field)) or _clean_graph_part(item.get("name"))
            if not ident:
                continue
            ctx.emit_resource(
                node_id=ctx.node_id(f"{svc}:{rtype}", item, ident),
                service=svc,
                rtype=rtype,
                kind=kind,
                label=label,
                name=_clean_graph_part(item.get("name")) or ident,
                attrs={
                    "resource_id": ident,
                    "location": _clean_graph_part(item.get("location")) or ctx.region,
                    "vpc_id": _clean_graph_part(item.get("vpc_id")),
                    **_recorded_exposure_attributes(item, "internet_exposed"),
                    "has_internet_route": bool(item.get("has_internet_route")),
                    "subnet_ids": list(item.get("subnet_ids", []) or []),
                    "network_exposure": list(item.get("network_exposure", []) or []),
                },
            )


def _add_ip_addresses(ctx: _NetworkInventoryContext, inventory: dict[str, Any]) -> None:
    """IP addresses (Elastic/reserved/public)."""
    for ip in _dict_items(inventory, "ip_addresses"):
        address = _clean_graph_part(ip.get("address"))
        if not address:
            continue
        node_id = ctx.node_id("network:ip_address", ip, address)
        ctx.emit_resource(
            node_id=node_id,
            service="network",
            rtype="ip_address",
            kind="ip-address",
            label="ip address",
            name=address,
            attrs={
                "resource_id": address,
                "ip_kind": _clean_graph_part(ip.get("kind")),
                "attached_to": _clean_graph_part(ip.get("attached_to")),
                "internet_exposed": True,
            },
        )
        attached_instance = ctx.instance_node_by_id.get(_clean_graph_part(ip.get("attached_to")))
        if attached_instance:
            _add_exposure_path_edge(ctx.graph, source=node_id, target=attached_instance, reason="elastic_ip_attachment")


def _wire_network_interface(ctx: _NetworkInventoryContext, eni: dict[str, Any], node_id: str, public_ip: str) -> None:
    instance_node_id = ctx.instance_node_by_id.get(_clean_graph_part(eni.get("instance_id")))
    if instance_node_id:
        ctx.part_of(node_id, instance_node_id)
        # Address attachment is configuration, not effective ingress evidence.
        if public_ip:
            _add_exposure_path_edge(ctx.graph, source=node_id, target=instance_node_id, reason="eni_public_ip")
    subnet_node_id = ctx.subnet_node_by_id.get(_clean_graph_part(eni.get("subnet_id")))
    if subnet_node_id:
        ctx.part_of(node_id, subnet_node_id)
    for sg_id in eni.get("security_group_ids", []) or []:
        sg_node_id = ctx.sg_node_by_id.get(_clean_graph_part(sg_id))
        if sg_node_id:
            ctx.part_of(node_id, sg_node_id)


def _add_network_interfaces(ctx: _NetworkInventoryContext, inventory: dict[str, Any]) -> None:
    """ENIs / NICs -> PART_OF instance + subnet + security group(s)."""
    for eni in _dict_items(inventory, "network_interfaces"):
        eni_id = _clean_graph_part(eni.get("id"))
        if not eni_id:
            continue
        node_id = ctx.node_id("network:network_interface", eni, eni_id)
        public_ip = _clean_graph_part(eni.get("public_ip"))
        ctx.emit_resource(
            node_id=node_id,
            service="network",
            rtype="network_interface",
            kind="network-interface",
            label="network interface",
            name=_clean_graph_part(eni.get("name")) or eni_id,
            attrs={
                "resource_id": eni_id,
                "vpc_id": _clean_graph_part(eni.get("vpc_id")),
                "subnet_id": _clean_graph_part(eni.get("subnet_id")),
                "private_ip": _clean_graph_part(eni.get("private_ip")),
                "public_ip": public_ip,
                "internet_exposed": bool(public_ip),
            },
        )
        _wire_network_interface(ctx, eni, node_id, public_ip)


def _add_web_acls(ctx: _NetworkInventoryContext, inventory: dict[str, Any]) -> None:
    """WAF / Cloud Armor web ACLs -> CLOUD_RESOURCE + PROTECTS."""
    for acl in _dict_items(inventory, "web_acls"):
        acl_id = _clean_graph_part(acl.get("id")) or _clean_graph_part(acl.get("arn")) or _clean_graph_part(acl.get("name"))
        if not acl_id:
            continue
        name = _clean_graph_part(acl.get("name")) or acl_id
        node_id = ctx.node_id("waf:web_acl", acl, acl_id)
        ctx.emit_resource(
            node_id=node_id,
            service="waf",
            rtype="waf",
            kind="web-acl",
            label="waf",
            name=name,
            attrs={"resource_id": _clean_graph_part(acl.get("arn")) or acl_id, "scope": _clean_graph_part(acl.get("scope"))},
        )
        ctx.protect(node_id, acl.get("protected_targets", []), "waf_web_acl_association")


def _api_gateway_items(inventory: dict[str, Any]) -> list[Any]:
    items = list(inventory.get("api_gateways", []) or [])
    for apim in inventory.get("api_management", []) or []:
        if isinstance(apim, dict):
            items.append(
                {
                    "name": apim.get("name"),
                    "id": apim.get("id") or apim.get("name"),
                    "protocol": "apim",
                    "endpoint": apim.get("gateway_url") or apim.get("endpoint") or "",
                    "internet_exposed": apim.get("internet_exposed"),
                    "stages": [],
                    "protected_targets": apim.get("protected_targets", []),
                    "location": apim.get("location"),
                }
            )
    return items


def _add_api_gateway(ctx: _NetworkInventoryContext, api: dict[str, Any], api_id: str) -> str:
    name = _clean_graph_part(api.get("name")) or api_id
    node_id = ctx.node_id("api_gateway", api, api_id).replace("cloud_resource:", "api_gateway:", 1)
    ctx.graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.API_GATEWAY,
            label=f"api gateway: {name}",
            attributes={
                "resource_id": _clean_graph_part(api.get("arn")) or api_id,
                "resource_name": name,
                "resource_type": "api_gateway",
                "cloud_provider": ctx.provider,
                "protocol": _clean_graph_part(api.get("protocol")),
                "endpoint": _clean_graph_part(api.get("endpoint")),
                "stages": list(api.get("stages", []) or []),
                **_recorded_exposure_attributes(api, "internet_exposed"),
                "location": _clean_graph_part(api.get("location")) or ctx.region,
                "account_id": ctx.account_id,
                "semantic_layer": "api_gateway",
            },
            data_sources=ctx.data_sources,
            dimensions=NodeDimensions(cloud_provider=ctx.provider, surface="api_gateway"),
        )
    )
    ctx.link_account(node_id)
    return node_id


def _add_api_gateways(ctx: _NetworkInventoryContext, inventory: dict[str, Any]) -> None:
    """API gateways -> API_GATEWAY nodes (+ Azure API Management) + PROTECTS."""
    for api in _api_gateway_items(inventory):
        if not isinstance(api, dict):
            continue
        api_id = _clean_graph_part(api.get("id")) or _clean_graph_part(api.get("arn")) or _clean_graph_part(api.get("name"))
        if not api_id:
            continue
        node_id = _add_api_gateway(ctx, api, api_id)
        # A configured frontend/backend binding says nothing about security
        # controls; an API gateway is not itself a WAF mitigation receipt.
        ctx.expose_targets(node_id, api.get("protected_targets", []), "api_gateway_frontend")


NETWORK_INVENTORY_STAGES = (
    _add_subnets,
    _add_edge_resources,
    _add_ip_addresses,
    _add_network_interfaces,
    _add_web_acls,
    _add_api_gateways,
)
