"""A pod's node VM is the same graph node inventory and side-scan give that VM, per provider."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.cloud.side_scan_inventory import side_scan_record
from agent_bom.cloud.side_scan_targets import CloudSideScanExecutionResult
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType
from agent_bom.models import Package

_SUB = "00000000-0000-0000-0000-000000000000"
_ARM = f"/subscriptions/{_SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/node-1"


def _k8s_agent(provider_id: str) -> dict[str, Any]:
    metadata = {"k8s_pod_uid": "u1", "k8s_pod": "p", "k8s_namespace": "n", "k8s_node": "node-1", "k8s_node_provider_id": provider_id}
    return {
        "name": "k8s-mcp",
        "type": "custom",
        "source": "kubernetes",
        "mcp_servers": [{"name": "billing", "surface": "mcp-server", "connection_metadata": metadata}],
    }


def _side_scan(provider: str, account: str, location: str, instance_id: str) -> dict[str, Any]:
    result = CloudSideScanExecutionResult(
        provider=provider,  # type: ignore[arg-type]
        target_type="disk",
        target_id="disk-1",
        account_id=account,
        location=location,
        packages=[Package(name="openssl", version="3.0.2", ecosystem="deb")],
    )
    record = side_scan_record(result, provider=provider)
    record.update(instance_id=instance_id, instance_name="node-1")
    return record


def _vms(report: dict[str, Any]) -> list[str]:
    graph = build_unified_graph_from_report(report)
    return [
        n.id for n in graph.nodes.values() if n.entity_type == EntityType.CLOUD_RESOURCE and n.attributes.get("resource_type") == "instance"
    ]


@pytest.mark.parametrize(
    ("provider", "account", "location", "instance_id", "provider_id"),
    [
        ("azure", _SUB, "eastus", _ARM, f"azure://{_ARM}"),
        ("gcp", "demo-proj", "us-central1-a", "1234567890123456789", "gce://demo-proj/us-central1-a/node-1"),
    ],
)
def test_pod_node_vm_and_side_scanned_vm_are_one_node(
    provider: str, account: str, location: str, instance_id: str, provider_id: str
) -> None:
    report = {
        "scan_id": "s",
        "agents": [_k8s_agent(provider_id)],
        "side_scan_results": [_side_scan(provider, account, location, instance_id)],
    }
    assert len(_vms(report)) == 1


def test_cve_on_the_node_vm_disk_is_an_attack_path_through_the_pod() -> None:
    from agent_bom.graph.path_derivation import _derived_attack_paths

    record = _side_scan("gcp", "demo-proj", "us-central1-a", "1234567890123456789")
    record["packages"][0]["vulnerabilities"] = [{"id": "CVE-2099-0010", "severity": "high"}]
    report = {"scan_id": "s", "agents": [_k8s_agent("gce://demo-proj/us-central1-a/node-1")], "side_scan_results": [record]}
    graph = build_unified_graph_from_report(report)
    paths = [p for p in _derived_attack_paths(graph) if p.target == "vuln:CVE-2099-0010"]
    assert any("container:k8s:pod:u1" in p.hops for p in paths), [p.hops for p in paths]


def test_pod_node_vm_and_gce_inventory_instance_are_one_node() -> None:
    instance = {"instance_id": "1234567890123456789", "name": "node-1", "zone": "us-central1-a", "project_id": "demo-proj"}
    inventory = {"status": "ok", "provider": "gcp", "project_id": "demo-proj", "account_id": "demo-proj", "instances": [instance]}
    alone = {"scan_id": "s", "cloud_inventory": [inventory]}
    assert len(_vms(alone)) == 1, "the inventory instance is projected"
    report = {**alone, "agents": [_k8s_agent("gce://demo-proj/us-central1-a/node-1")]}
    assert len(_vms(report)) == 1
