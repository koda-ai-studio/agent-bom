"""Internet exposure wiring for cloud network inventory (firewalls, load balancers, entry points)."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.normalization import coerce_truthy
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _gcp_firewall_applies(firewall_attrs: dict[str, Any], instance: dict[str, Any]) -> bool:
    """Return whether a permissive GCP firewall rule reaches *instance*.

    A rule applies when it is on the instance's network AND its target scope
    covers the instance. The target scope is: target tags (instance must carry
    one) OR target service accounts (instance must run as one). An EMPTY target
    set means the rule applies to ALL instances on its network — the GCP default.
    Missing network scope cannot establish that the rule applies.
    """
    fw_network = _clean_graph_part(firewall_attrs.get("fw_network"))
    inst_network = _clean_graph_part(instance.get("network"))
    if not fw_network or not inst_network or fw_network != inst_network:
        return False
    if coerce_truthy(firewall_attrs.get("fw_disabled")) or str(firewall_attrs.get("fw_direction") or "INGRESS").upper() != "INGRESS":
        return False

    target_tags = {str(t).strip() for t in (firewall_attrs.get("fw_target_tags") or []) if str(t).strip()}
    target_sas = {str(s).strip() for s in (firewall_attrs.get("fw_target_service_accounts") or []) if str(s).strip()}
    if not target_tags and not target_sas:
        # No targets → the rule applies to every instance on the network.
        return True
    instance_tags = {str(t).strip() for t in (instance.get("network_tags") or []) if str(t).strip()}
    if target_tags and instance_tags & target_tags:
        return True
    instance_sas = {str(s).strip() for s in (instance.get("service_accounts") or []) if str(s).strip()}
    if target_sas and instance_sas & target_sas:
        return True
    return False


def _apply_gcp_firewall_exposure(
    graph: UnifiedGraph,
    sg_node_by_id: dict[str, str],
    instance_nodes: list[tuple[str, dict[str, Any]]],
) -> None:
    """Record permissive firewall bindings without claiming effective ingress.

    Matching network and target scope establishes rule applicability. Priority,
    policy layers and return routing still require a reachability assessment.
    """
    firewall_nodes = [(graph.nodes.get(node_id), node_id) for node_id in sg_node_by_id.values()]
    permissive = [
        (node, node_id) for node, node_id in firewall_nodes if node is not None and coerce_truthy(node.attributes.get("internet_exposed"))
    ]
    if not permissive:
        return
    for inst_node_id, instance in instance_nodes:
        inst_node = graph.nodes.get(inst_node_id)
        if inst_node is None:
            continue
        # Only an instance with an external/public IP can be reached from the
        # internet; a permissive rule on a no-public-IP instance is not exposure.
        if not _clean_graph_part(instance.get("public_ip")):
            continue
        for fw_node, fw_node_id in permissive:
            if not _gcp_firewall_applies(fw_node.attributes, instance):
                continue
            _add_exposure_path_edge(
                graph,
                source=fw_node_id,
                target=inst_node_id,
                reason="permissive_firewall_external_ip",
            )


def _add_exposure_path_edge(
    graph: UnifiedGraph,
    *,
    source: str,
    target: str,
    reason: str,
    weight: float = 6.0,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Keep a configured network binding without inventing effective reachability.

    A binding alone does not evaluate routing, deny rules, listener state or
    traffic outcome. It is visible in Connections but cannot establish an
    attack-path hop until a complete network assessment is recorded.
    """
    if source not in graph.nodes or target not in graph.nodes or source == target:
        return
    for edge in graph.edges:
        if edge.source == source and edge.target == target and edge.relationship == RelationshipType.EXPOSED_TO:
            return
    graph.add_edge(
        UnifiedEdge(
            source=source,
            target=target,
            relationship=RelationshipType.EXPOSED_TO,
            weight=weight,
            traversable=False,
            evidence={
                **(evidence or {}),
                "source": "cloud-inventory",
                "tier": "static_scan",
                "reason": reason,
                "network_reachability": "unknown",
                "missing_evidence": ["effective_route_and_rule_evaluation", "observed_traffic"],
            },
        )
    )


def _instance_internet_reachable(graph: UnifiedGraph, inst_node_id: str, instance: dict[str, Any]) -> bool:
    node = graph.nodes.get(inst_node_id)
    if node is None:
        return False
    assessment = node.attributes.get("network_reachability_assessment")
    return (
        isinstance(assessment, dict)
        and assessment.get("complete") is True
        and assessment.get("decision") == "allow"
        and assessment.get("source_scope") == "internet"
        and assessment.get("target_id") == node.attributes.get("resource_id")
        and bool(assessment.get("evidence_refs"))
    )


def _link_internet_facing_load_balancers(
    graph: UnifiedGraph,
    load_balancers: list[tuple[str, str]],
    instance_nodes: list[tuple[str, dict[str, Any]]],
) -> None:
    """Link only registered instance targets from this inventory scope."""
    for lb_node_id, lb_vpc_id in load_balancers:
        lb_node = graph.nodes.get(lb_node_id)
        if lb_node is None:
            continue
        for binding in lb_node.attributes.get("backend_targets", []) or []:
            if not isinstance(binding, dict) or binding.get("target_type") != "instance":
                continue
            target_id = _clean_graph_part(binding.get("target_id"))
            group_arn = _clean_graph_part(binding.get("target_group_arn"))
            group_parts = group_arn.split(":", 5)
            if (
                not target_id
                or len(group_parts) != 6
                or group_parts[0] != "arn"
                or group_parts[2] != "elasticloadbalancing"
                or group_parts[3] != lb_node.attributes.get("location")
                or group_parts[4] != lb_node.attributes.get("account_id")
                or not group_parts[5].startswith("targetgroup/")
            ):
                continue
            candidates = [
                (nid, item)
                for nid, item in instance_nodes
                if _clean_graph_part(item.get("instance_id")) == target_id
                and (node := graph.nodes.get(nid)) is not None
                and node.attributes.get("account_id") == lb_node.attributes.get("account_id")
                and node.attributes.get("location") == lb_node.attributes.get("location")
            ]
            if len(candidates) != 1:
                continue
            inst_node_id, instance = candidates[0]
            inst_vpc = _clean_graph_part(instance.get("vpc_id"))
            target_vpc = _clean_graph_part(binding.get("vpc_id"))
            if not inst_vpc or not target_vpc or target_vpc != inst_vpc or (lb_vpc_id and lb_vpc_id != inst_vpc):
                continue
            _add_exposure_path_edge(
                graph,
                source=lb_node_id,
                target=inst_node_id,
                reason="registered_load_balancer_target",
                evidence={
                    key: binding[key]
                    for key in ("target_id", "target_type", "target_group_arn", "port", "protocol", "health_state")
                    if key in binding
                },
            )
