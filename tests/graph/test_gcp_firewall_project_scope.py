"""GCP firewall rule names are unique only within a project; graph identity must be project-scoped."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import RelationshipType

FW_A = "cloud_resource:gcp:compute:firewall:projects/proj-a/global/firewalls/allow-internal"
FW_B = "cloud_resource:gcp:compute:firewall:projects/proj-b/global/firewalls/allow-internal"
VM_A = "cloud_resource:gcp:compute:instance:scoped/proj-a///native/1001"
VM_B = "cloud_resource:gcp:compute:instance:scoped/proj-b///native/2002"


def _firewall(project: str, *, exposed: bool, target_tags: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "group_id": "allow-internal",
        "name": "allow-internal",
        "network": "default",
        "direction": "INGRESS",
        "internet_exposed": exposed,
        "network_exposure": [{"scope": "internet", "from_port": 22, "to_port": 22, "protocol": "tcp"}] if exposed else [],
        "source_ranges": ["0.0.0.0/0"] if exposed else ["10.0.0.0/8"],
        "target_tags": list(target_tags or []),
        "target_service_accounts": [],
        "project_id": project,
        **extra,
    }


def _inventory(project: str, instance_id: str, firewall: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": "gcp",
        "status": "ok",
        "project_id": project,
        "account_id": project,
        "buckets": [],
        "instances": [
            {
                "instance_id": instance_id,
                "name": f"vm-{project}",
                "public_ip": "34.0.0.1" if project == "proj-a" else "34.0.0.2",
                "network": "default",
                "network_tags": [],
                "service_accounts": [],
                "project_id": project,
            }
        ],
        "firewalls": [firewall],
        "service_accounts": [],
    }


def _inventories() -> list[dict[str, Any]]:
    return [
        _inventory("proj-a", "1001", _firewall("proj-a", exposed=True)),
        _inventory("proj-b", "2002", _firewall("proj-b", exposed=False)),
    ]


def _graph(inventories: list[dict[str, Any]]):
    return build_unified_graph_from_report({"agents": [], "cloud_inventory": inventories})


def _firewall_nodes(graph) -> dict[str, Any]:
    return {nid: node for nid, node in graph.nodes.items() if nid.startswith("cloud_resource:gcp:compute:firewall:")}


@pytest.mark.parametrize("reverse", [False, True], ids=["a-then-b", "b-then-a"])
def test_same_named_firewalls_in_two_projects_stay_distinct(reverse: bool) -> None:
    inventories = _inventories()
    if reverse:
        inventories.reverse()
    graph = _graph(inventories)

    firewalls = _firewall_nodes(graph)
    assert set(firewalls) == {FW_A, FW_B}
    assert firewalls[FW_A].attributes["account_id"] == "proj-a"
    assert firewalls[FW_B].attributes["account_id"] == "proj-b"
    assert firewalls[FW_A].attributes["project_id"] == "proj-a"
    assert firewalls[FW_B].attributes["project_id"] == "proj-b"
    # The native rule name and label survive; only identity gains project scope.
    for node in firewalls.values():
        assert node.attributes["resource_name"] == "allow-internal"
        assert node.label == "firewall: allow-internal"
    assert firewalls[FW_A].attributes["resource_id"] == "projects/proj-a/global/firewalls/allow-internal"
    assert firewalls[FW_A].attributes["internet_exposed"] is True
    assert firewalls[FW_B].attributes["internet_exposed"] is False
    assert firewalls[FW_A].attributes["fw_source_ranges"] == ["0.0.0.0/0"]
    assert firewalls[FW_B].attributes["fw_source_ranges"] == ["10.0.0.0/8"]


def test_firewall_identity_is_independent_of_inventory_order() -> None:
    forward = _graph(_inventories())
    backward = _graph(list(reversed(_inventories())))
    assert set(_firewall_nodes(forward)) == set(_firewall_nodes(backward))
    for node_id, node in _firewall_nodes(forward).items():
        other = _firewall_nodes(backward)[node_id]
        assert node.attributes["account_id"] == other.attributes["account_id"]
        assert node.attributes["internet_exposed"] == other.attributes["internet_exposed"]


@pytest.mark.parametrize("reverse", [False, True], ids=["a-then-b", "b-then-a"])
def test_firewall_exposure_matches_only_the_instances_own_project(reverse: bool) -> None:
    inventories = _inventories()
    if reverse:
        inventories.reverse()
    graph = _graph(inventories)

    exposed = {(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.EXPOSED_TO and e.source in {FW_A, FW_B}}
    assert exposed == {(FW_A, VM_A)}
    assert not graph.nodes[VM_A].attributes.get("internet_exposed")
    assert all(not e.traversable for e in graph.edges if e.relationship == RelationshipType.EXPOSED_TO and e.source in {FW_A, FW_B})
    # proj-b's own rule is internal-only; proj-a's permissive rule must not leak across projects.
    assert not graph.nodes[VM_B].attributes.get("internet_exposed")


def test_self_link_supplies_project_scope_when_record_lacks_project_id() -> None:
    firewall = _firewall(
        "",
        exposed=True,
        self_link="https://www.googleapis.com/compute/v1/projects/proj-a/global/firewalls/allow-internal",
    )
    firewall.pop("project_id")
    inventory = _inventory("proj-a", "1001", firewall)
    inventory.pop("project_id")
    inventory.pop("account_id")
    graph = _graph([inventory])
    assert set(_firewall_nodes(graph)) == {FW_A}


def test_inventory_project_scopes_legacy_firewall_records() -> None:
    firewall = _firewall("proj-b", exposed=False)
    firewall.pop("project_id")
    graph = _graph([_inventory("proj-b", "2002", firewall)])
    assert set(_firewall_nodes(graph)) == {FW_B}


def test_already_scoped_group_id_is_not_double_scoped() -> None:
    firewall = _firewall("proj-a", exposed=True, group_id="projects/proj-a/global/firewalls/allow-internal")
    graph = _graph([_inventory("proj-a", "1001", firewall)])
    assert set(_firewall_nodes(graph)) == {FW_A}


def test_aws_local_ids_are_scoped_and_azure_ids_are_case_normalized() -> None:
    aws = {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "buckets": [],
        "instances": [],
        "security_groups": [{"group_id": "sg-0abc", "name": "web"}],
        "roles": [],
        "users": [],
    }
    nsg_id = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg"
    azure = {
        "provider": "azure",
        "status": "ok",
        "account_id": "sub-1",
        "storage_accounts": [],
        "instances": [],
        "security_groups": [{"group_id": nsg_id, "name": "web-nsg"}],
    }
    graph = _graph([aws, azure])
    assert "cloud_resource:aws:ec2:security-group:scoped/111122223333/us-east-1//native/sg-0abc" in graph.nodes
    assert f"cloud_resource:azure:network:network-security-group:{nsg_id.lower()}" in graph.nodes
