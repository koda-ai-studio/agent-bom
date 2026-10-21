"""Network inventory is not a substitute for a recorded connection or reachability assessment."""

from __future__ import annotations

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.builder_network_exposure import _gcp_firewall_applies, _instance_internet_reachable
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _inventory():
    return {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "instances": [{"instance_id": "i-1", "vpc_id": "vpc-1", "subnet_id": "subnet-1", "public_ip": "198.51.100.1"}],
        "elb_load_balancers": [
            {
                "name": "frontend",
                "arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/frontend/1",
                "vpc_id": "vpc-1",
                "internet_exposed": True,
            }
        ],
        "subnets": [{"id": "subnet-1", "vpc_id": "vpc-1", "is_public": True}],
        "internet_gateways": [{"id": "igw-1", "vpc_id": "vpc-1"}],
    }


def _build(inventory):
    return build_unified_graph_from_report({"cloud_inventory": inventory})


def _resource(graph, kind):
    return next(n for n in graph.nodes.values() if n.attributes.get("resource_type") == kind)


def test_same_vpc_never_invents_load_balancer_backend():
    graph = _build(_inventory())
    lb, instance = _resource(graph, "load_balancer"), _resource(graph, "instance")
    assert not any(e.source == lb.id and e.target == instance.id for e in graph.edges)


def test_recorded_private_backend_is_connected_without_claiming_effective_reachability():
    inventory = _inventory()
    inventory["instances"][0].pop("public_ip")
    inventory["elb_load_balancers"][0]["backend_targets"] = [
        {
            "target_id": "i-1",
            "target_type": "instance",
            "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/1",
            "port": 443,
            "vpc_id": "vpc-1",
        }
    ]
    graph = _build(inventory)
    lb, instance = _resource(graph, "load_balancer"), _resource(graph, "instance")
    edges = [e for e in graph.edges if e.source == lb.id and e.target == instance.id]
    assert len(edges) == 1
    assert edges[0].evidence["reason"] == "registered_load_balancer_target"
    assert edges[0].evidence["network_reachability"] == "unknown"
    assert edges[0].evidence["port"] == 443
    assert edges[0].traversable is False


@pytest.mark.parametrize("evidence", [{"public_ip": "198.51.100.1"}, {"internet_exposed": True}])
def test_address_or_exposure_flag_is_not_a_complete_network_assessment(evidence):
    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="instance", entity_type=EntityType.CLOUD_RESOURCE, label="instance", attributes=evidence))
    assert not _instance_internet_reachable(graph, "instance", evidence)


def test_public_subnet_does_not_make_every_instance_internet_reachable():
    graph = _build(_inventory())
    instance = _resource(graph, "instance")
    assert not any(e.target == instance.id and e.relationship == RelationshipType.EXPOSED_TO and e.traversable for e in graph.edges)


def test_public_interface_preserves_attachment_without_marking_vm_reachable():
    inventory = _inventory()
    inventory["network_interfaces"] = [{"id": "eni-1", "instance_id": "i-1", "subnet_id": "subnet-1", "public_ip": "198.51.100.1"}]
    graph = _build(inventory)
    instance, interface = _resource(graph, "instance"), _resource(graph, "network_interface")
    assert instance.attributes.get("internet_exposed") is not True
    assert any(e.source == interface.id and e.target == instance.id and e.relationship == RelationshipType.PART_OF for e in graph.edges)
    assert not any(
        e.source == interface.id and e.target == instance.id and e.traversable and e.relationship == RelationshipType.EXPOSED_TO
        for e in graph.edges
    )


def test_waf_association_does_not_invent_public_ingress():
    inventory = _inventory()
    inventory["elb_load_balancers"][0]["internet_exposed"] = False
    inventory["web_acls"] = [{"id": "waf-1", "protected_targets": [inventory["elb_load_balancers"][0]["arn"]]}]
    graph = _build(inventory)
    waf, lb = _resource(graph, "waf"), _resource(graph, "load_balancer")
    assert any(e.source == waf.id and e.target == lb.id and e.relationship == RelationshipType.PROTECTS for e in graph.edges)
    assert waf.attributes.get("internet_exposed") is not True
    assert not any(e.source == waf.id and e.relationship == RelationshipType.EXPOSED_TO for e in graph.edges)


def test_waf_association_is_not_proof_that_a_vulnerability_is_mitigated():
    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="asset", entity_type=EntityType.CLOUD_RESOURCE, label="asset", attributes={"internet_exposed": True}))
    graph.add_node(
        UnifiedNode(
            id="cve",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-test",
            severity="high",
            attributes={"reachability": "likely", "reachability_basis": ["dependency_path"]},
        )
    )
    graph.add_node(UnifiedNode(id="waf", entity_type=EntityType.CLOUD_RESOURCE, label="waf", attributes={"resource_type": "waf"}))
    graph.add_edge(UnifiedEdge(source="waf", target="asset", relationship=RelationshipType.PROTECTS))
    graph.add_edge(UnifiedEdge(source="asset", target="cve", relationship=RelationshipType.VULNERABLE_TO))
    apply_cnapp_overlay(graph)
    assert graph.nodes["asset"].attributes.get("exposure_mitigated") is not True
    assert graph.nodes["asset"].attributes.get("toxic_exposed_vulnerable_mitigated") is not True
    assert graph.nodes["asset"].attributes.get("waf_association_recorded") is True


def test_api_gateway_backend_is_not_automatically_a_waf_protection():
    inventory = _inventory()
    inventory["api_gateways"] = [
        {"name": "api", "id": "api-1", "internet_exposed": True, "protected_targets": [inventory["elb_load_balancers"][0]["arn"]]}
    ]
    graph = _build(inventory)
    api = _resource(graph, "api_gateway")
    assert not any(e.source == api.id and e.relationship == RelationshipType.PROTECTS for e in graph.edges)


def test_legacy_waf_flag_does_not_lower_path_risk_or_claim_mitigation():
    from agent_bom.graph.path_derivation import _fusion_signals_for_path

    graph = UnifiedGraph()
    graph.add_node(
        UnifiedNode(
            id="asset",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="asset",
            attributes={"internet_exposed": True, "protected_by_waf": True, "exposure_mitigated": True},
        )
    )
    signals = _fusion_signals_for_path(graph, ["asset"])
    assert signals[0][0] == "internet_exposed"
    assert "reachable from the public internet" not in signals[0][2]
    assert "mitigated" not in signals[0][2]


def test_resource_name_alone_does_not_resolve_a_protected_target():
    inventory = _inventory()
    inventory["web_acls"] = [{"id": "waf-1", "protected_targets": ["frontend"]}]
    graph = _build(inventory)
    waf = _resource(graph, "waf")
    assert not any(e.source == waf.id and e.relationship == RelationshipType.PROTECTS for e in graph.edges)


@pytest.mark.parametrize(
    ("firewall", "instance"),
    [
        ({"fw_network": "projects/p/global/networks/n"}, {}),
        ({}, {"network": "projects/p/global/networks/n"}),
        ({"fw_network": "projects/p/global/networks/n", "fw_disabled": True}, {"network": "projects/p/global/networks/n"}),
        ({"fw_network": "projects/p/global/networks/n", "fw_direction": "EGRESS"}, {"network": "projects/p/global/networks/n"}),
    ],
)
def test_missing_network_or_disabled_egress_firewall_cannot_establish_ingress(firewall, instance):
    assert not _gcp_firewall_applies(firewall, instance)


def test_private_apim_does_not_become_public_by_normalization():
    inventory = {
        "provider": "azure",
        "status": "ok",
        "subscription_id": "sub-1",
        "api_management": [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ApiManagement/service/internal",
                "name": "internal",
                "internet_exposed": False,
                "public_network_access": "Disabled",
            }
        ],
    }
    graph = _build(inventory)
    api = _resource(graph, "api_gateway")
    assert api.attributes.get("internet_exposed") is not True


@pytest.mark.parametrize("deny", [False, True])
def test_native_target_discovery_records_binding_and_denied_coverage(deny):
    from agent_bom.cloud.aws_inv.edge import _discover_elb

    class Paginator:
        def __init__(self, operation):
            self.operation = operation

        def paginate(self, **kwargs):
            if self.operation == "describe_load_balancers":
                return [
                    {
                        "LoadBalancers": [
                            {"LoadBalancerName": "frontend", "LoadBalancerArn": "arn:lb", "VpcId": "vpc-1", "Scheme": "internet-facing"}
                        ]
                    }
                ]
            assert self.operation == "describe_target_groups" and kwargs == {"LoadBalancerArn": "arn:lb"}
            return [{"TargetGroups": [{"TargetGroupArn": "arn:tg", "TargetType": "instance", "VpcId": "vpc-1", "Protocol": "HTTP"}]}]

    class Client:
        def get_paginator(self, operation):
            return Paginator(operation)

        def describe_target_health(self, **kwargs):
            assert kwargs == {"TargetGroupArn": "arn:tg"}
            if deny:
                raise PermissionError("AccessDenied")
            return {"TargetHealthDescriptions": [{"Target": {"Id": "i-1", "Port": 8080}, "TargetHealth": {"State": "healthy"}}]}

    class Session:
        def client(self, service, **kwargs):
            assert service == "elbv2"
            return Client()

    warnings, missing = [], []
    records = _discover_elb(Session(), "us-east-1", account_id="111122223333", warnings=warnings, missing=missing)
    assert len(records) == 1
    assert records[0]["backend_collection_complete"] is (not deny)
    if deny:
        assert records[0]["backend_targets"] == []
        assert missing and warnings
    else:
        assert records[0]["backend_targets"] == [
            {
                "target_id": "i-1",
                "target_type": "instance",
                "target_group_arn": "arn:tg",
                "port": 8080,
                "protocol": "HTTP",
                "vpc_id": "vpc-1",
                "health_state": "healthy",
            }
        ]
        assert not missing and not warnings


def test_configuration_only_binding_survives_restart_without_becoming_traversable(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    inventory = _inventory()
    inventory["elb_load_balancers"][0]["backend_targets"] = [
        {
            "target_id": "i-1",
            "target_type": "instance",
            "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/1",
            "port": 443,
            "vpc_id": "vpc-1",
        }
    ]
    graph = _build(inventory)
    graph.scan_id, graph.tenant_id = "network-evidence", "tenant-a"
    path = tmp_path / "graph.db"
    SQLiteGraphStore(path).save_graph(graph)
    loaded = SQLiteGraphStore(path).load_graph(tenant_id="tenant-a", scan_id="network-evidence")
    bindings = [e for e in loaded.edges if e.evidence.get("reason") == "registered_load_balancer_target"]
    assert len(bindings) == 1
    assert bindings[0].traversable is False
    assert bindings[0].evidence["network_reachability"] == "unknown"
    assert not SQLiteGraphStore(path).load_graph(tenant_id="tenant-b", scan_id="network-evidence").nodes


def test_unassessed_network_binding_cannot_become_toxic_path_or_sensitive_access():
    from agent_bom.graph.path_derivation import _derived_toxic_combination_paths

    graph = UnifiedGraph()
    graph.add_node(
        UnifiedNode(
            id="asset",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="asset",
            attributes={"internet_exposed": True, "toxic_exposed_vulnerable": True},
        )
    )
    graph.add_node(UnifiedNode(id="data", entity_type=EntityType.DATA_STORE, label="data", attributes={"data_sensitivity": "pii"}))
    graph.add_edge(
        UnifiedEdge(
            source="asset",
            target="data",
            relationship=RelationshipType.EXPOSED_TO,
            traversable=False,
            evidence={"network_reachability": "unknown", "source": "cloud-inventory"},
        )
    )
    assert _derived_toxic_combination_paths(graph) == []
    apply_cnapp_overlay(graph)
    assert not graph.nodes["data"].attributes.get("sensitive_data_access_count")


@pytest.mark.parametrize(
    ("routes", "expected"),
    [
        ([{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"}], True),
        ([{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "blackhole"}], False),
        ([{"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1", "State": "active"}], True),
    ],
)
def test_subnet_classification_uses_effective_routes_not_auto_public_ip(routes, expected):
    from agent_bom.cloud.aws_inv.network import _discover_network_edge

    class Paginator:
        def __init__(self, operation):
            self.operation = operation

        def paginate(self):
            if self.operation == "describe_route_tables":
                return [
                    {"RouteTables": [{"RouteTableId": "rtb-main", "VpcId": "vpc-1", "Routes": routes, "Associations": [{"Main": True}]}]}
                ]
            if self.operation == "describe_subnets":
                return [{"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "MapPublicIpOnLaunch": False}]}]
            return [{}]

    class Client:
        def get_paginator(self, operation):
            return Paginator(operation)

        def describe_internet_gateways(self):
            return {}

        def describe_egress_only_internet_gateways(self):
            return {}

    class Session:
        def client(self, *_args, **_kwargs):
            return Client()

    result = _discover_network_edge(Session(), "us-east-1", account_id="111122223333", warnings=[])
    assert result["subnets"][0]["is_public"] is expected
    assert result["subnets"][0]["route_table_id"] == "rtb-main"


@pytest.mark.parametrize("complete", [False, True])
def test_explicit_private_route_overrides_public_main_and_missing_reads_stay_unknown(complete):
    from agent_bom.cloud.aws_inv.network import _apply_subnet_routes

    rows = {
        "subnets": [{"id": "subnet-1", "vpc_id": "vpc-1"}],
        "route_tables": [
            {
                "id": "public-main",
                "vpc_id": "vpc-1",
                "routes": [{"GatewayId": "igw-1", "DestinationCidrBlock": "0.0.0.0/0", "State": "active"}],
                "associations": [{"Main": True}],
            },
            {
                "id": "private-override",
                "vpc_id": "vpc-1",
                "routes": [{"NatGatewayId": "nat-1", "DestinationCidrBlock": "0.0.0.0/0", "State": "active"}],
                "associations": [{"SubnetId": "subnet-1"}],
            },
        ],
    }
    _apply_subnet_routes(rows, complete=complete)
    assert rows["subnets"][0]["is_public"] is (False if complete else None)
    assert rows["subnets"][0]["internet_gateway_ids"] == []


def test_gateway_needs_an_explicit_subnet_route_binding():
    graph = _build(_inventory())
    gateway, subnet = _resource(graph, "internet_gateway"), _resource(graph, "subnet")
    assert not any(e.source == gateway.id and e.target == subnet.id for e in graph.edges)


@pytest.mark.parametrize("public", [True, False])
def test_subnet_placement_is_structural_for_public_and_private_subnets(public):
    inventory = _inventory()
    inventory["subnets"][0]["is_public"] = public
    graph = _build(inventory)
    instance, subnet = _resource(graph, "instance"), _resource(graph, "subnet")
    assert any(e.source == instance.id and e.target == subnet.id and e.relationship == RelationshipType.PART_OF for e in graph.edges)
    assert not any(e.source == subnet.id and e.target == instance.id and e.relationship == RelationshipType.EXPOSED_TO for e in graph.edges)


def test_pending_explicit_route_does_not_fall_back_to_public_main():
    from agent_bom.cloud.aws_inv.network import _apply_subnet_routes

    rows = {
        "subnets": [{"id": "subnet-1", "vpc_id": "vpc-1"}],
        "route_tables": [
            {
                "id": "public-main",
                "vpc_id": "vpc-1",
                "routes": [{"GatewayId": "igw-1", "DestinationCidrBlock": "0.0.0.0/0", "State": "active"}],
                "associations": [{"Main": True}],
            },
            {
                "id": "pending-override",
                "vpc_id": "vpc-1",
                "routes": [],
                "associations": [{"SubnetId": "subnet-1", "AssociationState": {"State": "associating"}}],
            },
        ],
    }
    _apply_subnet_routes(rows, complete=True)
    assert rows["subnets"][0]["is_public"] is None


@pytest.mark.parametrize(
    "group_arn",
    [
        "arn:aws:elasticloadbalancing:us-west-2:111122223333:targetgroup/app/1",
        "arn:aws:elasticloadbalancing:us-east-1:999999999999:targetgroup/app/1",
        "app",
    ],
)
def test_backend_reference_must_match_native_account_and_region(group_arn):
    inventory = _inventory()
    inventory["elb_load_balancers"][0]["backend_targets"] = [
        {
            "target_id": "i-1",
            "target_type": "instance",
            "target_group_arn": group_arn,
            "vpc_id": "vpc-1",
        }
    ]
    graph = _build(inventory)
    assert not any(e.evidence.get("reason") == "registered_load_balancer_target" for e in graph.edges)


def test_derived_sensitive_path_retains_the_recorded_relationship():
    from agent_bom.graph.path_derivation import _derived_toxic_combination_paths

    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="asset", entity_type=EntityType.CLOUD_RESOURCE, label="asset", attributes={"internet_exposed": True}))
    graph.add_node(UnifiedNode(id="data", entity_type=EntityType.DATA_STORE, label="data", attributes={"data_sensitivity": "pii"}))
    graph.add_edge(UnifiedEdge(source="asset", target="data", relationship=RelationshipType.STORES))
    paths = _derived_toxic_combination_paths(graph)
    assert len(paths) == 1
    assert paths[0].edges == ["stores"]


@pytest.mark.parametrize("scope", ["account", "region"])
def test_network_inventory_ids_and_placements_do_not_merge_across_scopes(scope):
    from copy import deepcopy

    first = _inventory()
    second = deepcopy(first)
    if scope == "account":
        second["account_id"] = "999999999999"
        second["elb_load_balancers"] = []
    else:
        second["region"] = "us-west-2"
        second["elb_load_balancers"] = []
    graph = build_unified_graph_from_report({"cloud_inventory": [first, second]})
    for kind in ("instance", "subnet", "internet_gateway"):
        nodes = [n for n in graph.nodes.values() if n.attributes.get("resource_type") == kind]
        assert len(nodes) == 2, kind
    for edge in graph.edges:
        if edge.evidence.get("reason") == "instance_subnet_attachment":
            src, dst = graph.nodes[edge.source], graph.nodes[edge.target]
            assert src.attributes["account_id"] == dst.attributes["account_id"]
            assert src.attributes["location"] == dst.attributes["location"]


def test_kubernetes_host_without_account_does_not_join_an_account_qualified_vm():
    from tests.test_graph_hosted_on import VM, _k8s_agent, _vm_cve
    from tests.test_graph_hosted_on import _inventory as vm_inventory

    agent = _k8s_agent()
    agent["mcp_servers"][0]["connection_metadata"].pop("k8s_cloud_account_id")
    graph = build_unified_graph_from_report({"agents": [agent], "cloud_inventory": vm_inventory(), "findings": [_vm_cve()]})
    assert VM in graph.nodes
    assert not any(e.relationship == RelationshipType.HOSTED_ON and e.target == VM for e in graph.edges)


def test_name_only_resource_cannot_satisfy_a_native_backend_reference():
    inventory = _inventory()
    inventory["elb_load_balancers"][0].pop("arn")
    inventory["api_gateways"] = [{"id": "api-1", "protected_targets": ["frontend"]}]
    graph = _build(inventory)
    assert not any(e.evidence.get("reason") == "api_gateway_frontend" for e in graph.edges)


def test_shared_vpc_is_not_the_identity_of_two_load_balancers():
    from agent_bom.core.cloud_identity import cloud_resource_node_id

    first = {"name": "first", "vpc_id": "vpc-1"}
    second = {"name": "second", "vpc_id": "vpc-1"}

    def key(row):
        return cloud_resource_node_id("aws", "elbv2:load_balancer", row, "111122223333", "us-east-1")

    assert key(first) != key(second)


def test_protection_association_is_not_an_attack_path_hop():
    from agent_bom.graph.relationship_specs import relationship_spec

    assert relationship_spec(RelationshipType.PROTECTS).default_traversable is False
    inventory = _inventory()
    inventory["web_acls"] = [{"id": "waf-1", "protected_targets": [inventory["elb_load_balancers"][0]["arn"]]}]
    graph = _build(inventory)
    assert all(not e.traversable for e in graph.edges if e.relationship == RelationshipType.PROTECTS)
