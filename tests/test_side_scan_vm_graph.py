"""Side-scan packages and CVEs land on the VM node, not on a detached count."""

from __future__ import annotations

from agent_bom.cloud.side_scan import SideScanResult
from agent_bom.cloud.side_scan_inventory import MAX_SIDE_SCAN_PACKAGES, side_scan_record
from agent_bom.cloud.side_scan_targets import CloudSideScanExecutionResult
from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.models import Package, Severity, Vulnerability

ACCOUNT = "000000000000"


def _vulnerable_openssl() -> Package:
    return Package(
        name="openssl",
        version="3.0.2-0ubuntu1",
        ecosystem="deb",
        purl="pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1",
        vulnerabilities=[Vulnerability(id="CVE-2099-0001", summary="synthetic", severity=Severity.HIGH, is_kev=True)],
    )


def _aws_result() -> SideScanResult:
    return SideScanResult(
        instance_id="i-0123456789abcdef0",
        volume_id="vol-0aaa",
        snapshot_id="snap-0bbb",
        account_id=ACCOUNT,
        region="us-east-1",
        packages=[_vulnerable_openssl(), Package(name="zlib", version="1.2.11", ecosystem="deb")],
        cleaned_up=True,
    )


def _edges(graph, source: str, rel: RelationshipType) -> list[str]:
    return [edge.target for edge in graph.edges if edge.source == source and edge.relationship == rel]


def test_aws_record_carries_packages_cves_and_owning_instance() -> None:
    record = side_scan_record(_aws_result(), provider="aws")

    assert record["instance_id"] == "i-0123456789abcdef0"
    assert record["account_id"] == ACCOUNT
    assert record["region"] == "us-east-1"
    assert record["package_count"] == 2
    assert record["vulnerability_count"] == 1
    assert record["vulnerable_package_count"] == 1
    assert record["packages_truncated"] is False
    first = record["packages"][0]
    assert first["name"] == "openssl"
    assert first["vulnerabilities"][0]["id"] == "CVE-2099-0001"
    assert first["vulnerabilities"][0]["is_kev"] is True


def test_record_caps_packages_with_explicit_truncation_and_vulnerable_first() -> None:
    packages = [Package(name=f"lib{i}", version="1", ecosystem="deb") for i in range(MAX_SIDE_SCAN_PACKAGES + 5)]
    packages.append(_vulnerable_openssl())
    result = SideScanResult(instance_id="i-0123456789abcdef0", account_id=ACCOUNT, region="us-east-1", packages=packages)

    record = side_scan_record(result, provider="aws")

    assert len(record["packages"]) == MAX_SIDE_SCAN_PACKAGES
    assert record["packages_truncated"] is True
    assert record["packages_omitted"] == 6
    assert record["package_count"] == MAX_SIDE_SCAN_PACKAGES + 6
    assert record["packages"][0]["name"] == "openssl"


def test_aws_side_scan_cves_attach_to_the_inventory_instance_node_and_form_a_path() -> None:
    instance = {"instance_id": "i-0123456789abcdef0", "name": "web-1", "region": "us-east-1", "account_id": ACCOUNT}
    report = {
        "scan_id": "s1",
        "cloud_inventory": {"status": "ok", "provider": "aws", "account_id": ACCOUNT, "region": "us-east-1", "instances": [instance]},
        "side_scan_results": [side_scan_record(_aws_result(), provider="aws")],
    }

    graph = build_unified_graph_from_report(report)

    vm_id = cloud_resource_node_id("aws", "ec2:instance", {**instance, "id": instance["instance_id"]}, ACCOUNT, "us-east-1")
    vm = graph.nodes[vm_id]
    assert vm.attributes["side_scan_package_count"] == 2
    assert vm.attributes["side_scan_vulnerability_count"] == 1
    vm_packages = _edges(graph, vm_id, RelationshipType.CONTAINS)
    openssl = next(pkg for pkg in vm_packages if "openssl" in pkg)
    assert "vuln:CVE-2099-0001" in _edges(graph, openssl, RelationshipType.VULNERABLE_TO)
    assert len([n for n in graph.nodes.values() if n.entity_type == EntityType.CLOUD_RESOURCE and n.label.startswith("ec2")]) == 1

    paths = [path for path in _derived_attack_paths(graph) if path.target == "vuln:CVE-2099-0001"]
    assert paths, "a side-scan CVE on a VM must produce an attack path"
    assert paths[0].hops[0] == vm_id
    assert paths[0].hops[-1] == "vuln:CVE-2099-0001"


def test_azure_disk_owner_vm_matches_inventory_id_case_insensitively() -> None:
    vm_arm = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/App-1"
    result = CloudSideScanExecutionResult(
        provider="azure",
        target_type="managed_disk",
        target_id=vm_arm.replace("virtualMachines/App-1", "disks/os"),
        account_id="00000000-0000-0000-0000-000000000000",
        location="eastus",
        instance_id=vm_arm,
        packages=[_vulnerable_openssl()],
    )
    report = {
        "side_scan_results": [side_scan_record(result, provider="azure")],
        "cloud_inventory": {
            "status": "ok",
            "provider": "azure",
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "instances": [{"instance_id": vm_arm.lower(), "name": "App-1", "location": "eastus"}],
        },
    }

    graph = build_unified_graph_from_report(report)

    vm_id = f"cloud_resource:azure:compute:instance:{vm_arm.casefold()}"
    assert graph.nodes[vm_id].attributes["resource_kind"] == "azure-vm"
    instances = [n for n in graph.nodes.values() if n.attributes.get("resource_type") == "instance"]
    assert [n.id for n in instances] == [vm_id]
    assert any("openssl" in pkg for pkg in _edges(graph, vm_id, RelationshipType.CONTAINS))


def test_gcp_disk_owner_vm_uses_the_inventory_numeric_id_key() -> None:
    result = CloudSideScanExecutionResult(
        provider="gcp",
        target_type="persistent_disk",
        target_id="projects/demo-proj/zones/us-central1-a/disks/os",
        account_id="demo-proj",
        location="us-central1-a",
        instance_id="1234567890123",
        instance_name="api-1",
        packages=[_vulnerable_openssl()],
    )
    graph = build_unified_graph_from_report({"side_scan_results": [side_scan_record(result, provider="gcp")]})

    inventory_record = {"id": "1234567890123", "zone": "us-central1-a", "project_id": "demo-proj"}
    vm_id = cloud_resource_node_id("gcp", "compute:instance", inventory_record, "demo-proj", "")
    assert vm_id in graph.nodes
    assert graph.nodes[vm_id].attributes["resource_type"] == "instance"


def test_unattached_disk_keeps_packages_on_the_disk_target_node() -> None:
    result = CloudSideScanExecutionResult(
        provider="gcp",
        target_type="persistent_disk",
        target_id="projects/demo-proj/zones/us-central1-a/disks/data",
        account_id="demo-proj",
        location="us-central1-a",
        packages=[_vulnerable_openssl()],
    )
    graph = build_unified_graph_from_report({"side_scan_results": [side_scan_record(result, provider="gcp")]})

    disk_id = "cloud_resource:gcp:cwpp:persistent_disk:projects/demo-proj/zones/us-central1-a/disks/data"
    assert graph.nodes[disk_id].attributes["resource_type"] == "workload_disk"
    assert any("openssl" in pkg for pkg in _edges(graph, disk_id, RelationshipType.CONTAINS))


def test_ami_scan_links_instances_launched_from_it() -> None:
    image = SideScanResult(image_id="ami-0fedcba9876543210", snapshot_id="snap-ami", account_id=ACCOUNT, region="us-east-1")
    image.packages = [_vulnerable_openssl()]
    instance = {
        "instance_id": "i-0123456789abcdef0",
        "image_id": "ami-0fedcba9876543210",
        "region": "us-east-1",
        "account_id": ACCOUNT,
    }
    report = {
        "cloud_inventory": {"status": "ok", "provider": "aws", "account_id": ACCOUNT, "region": "us-east-1", "instances": [instance]},
        "side_scan_results": [side_scan_record(image, provider="aws")],
    }

    graph = build_unified_graph_from_report(report)

    image_id = "cloud_resource:aws:cwpp:ami:ami-0fedcba9876543210"
    assert graph.nodes[image_id].attributes["resource_type"] == "machine_image"
    vm_id = cloud_resource_node_id("aws", "ec2:instance", {**instance, "id": instance["instance_id"]}, ACCOUNT, "us-east-1")
    assert image_id in _edges(graph, vm_id, RelationshipType.DEPENDS_ON)
    paths = [path for path in _derived_attack_paths(graph) if path.target == "vuln:CVE-2099-0001"]
    assert any(path.hops[:2] == [vm_id, image_id] for path in paths)


def test_side_scan_section_round_trips_through_report_json_and_graph_evidence() -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json
    from agent_bom.output.graph_evidence import graph_evidence_sections, has_graph_evidence

    record = side_scan_record(_aws_result(), provider="aws")
    report = AIBOMReport(agents=[], blast_radii=[])
    report.side_scan_results_data = [record]

    assert to_json(report)["side_scan_results"] == [record]
    assert has_graph_evidence(report)
    assert graph_evidence_sections(report)["side_scan_results"] == [record]
