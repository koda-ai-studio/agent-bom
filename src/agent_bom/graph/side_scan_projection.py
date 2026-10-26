"""Side-scan packages and CVEs held by the VM (or machine image) they were read from.

A disk side-scan records the instance that owns the disk when the provider
says so (AWS volume attachment, Azure ``managed_by``, GCE ``users``). The VM
node is keyed exactly as cloud inventory keys it, so packages and CVEs land
on the same node an inventory scan produced and attack paths walk
VM -> package -> CVE. A disk with no recorded owner keeps its packages on the
side-scan target node; a machine image keeps them on an image node that
instances launched from it depend on.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.canonical_ids import canonical_graph_node_id, source_ids
from agent_bom.core.cloud_identity import cloud_resource_node_id, gce_instance_self_link
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.package_projection import _add_vuln_node, _package_evidence, _package_node_id
from agent_bom.graph.types import EntityType, RelationshipType

SOURCE = "cwpp-side-scan"
_IMAGE_TYPES = frozenset({"ami", "image", "machine_image"})


def _text(record: Mapping[str, Any], key: str) -> str:
    return str(record.get(key) or "").strip()


def _instance_node_id(record: Mapping[str, Any]) -> str:
    provider, instance, account = _text(record, "provider"), _text(record, "instance_id"), _text(record, "account_id")
    if provider == "aws":
        region = _text(record, "region")
        return cloud_resource_node_id("aws", "ec2:instance", {"id": instance, "account_id": account, "region": region}, account, region)
    if provider == "azure":
        return cloud_resource_node_id("azure", "compute:instance", {"id": instance}, account, _text(record, "location"))
    zone = _text(record, "location")
    return cloud_resource_node_id("gcp", "compute:instance", {"id": instance, "zone": zone, "project_id": account}, account, "")


def _holder(record: Mapping[str, Any]) -> tuple[str, dict[str, Any], str]:
    """``(node id, attributes, label)`` of the node that holds the scanned packages."""
    provider, target_type, target_id = _text(record, "provider"), _text(record, "target_type"), _text(record, "target_id")
    base = {"cloud_provider": provider, "account_id": _text(record, "account_id"), "location": _text(record, "location")}
    if _text(record, "instance_id") and target_type not in _IMAGE_TYPES:
        name = _text(record, "instance_name") or _text(record, "instance_id").rstrip("/").rsplit("/", 1)[-1]
        attrs = {**base, "resource_id": _text(record, "instance_id"), "resource_name": name, "resource_type": "instance"}
        if provider == "gcp" and (link := gce_instance_self_link(base["account_id"], base["location"], _text(record, "instance_name"))):
            attrs["self_link"] = link
        return _instance_node_id(record), attrs, f"vm: {name}"
    image = target_type in _IMAGE_TYPES
    name = target_id.rstrip("/").rsplit("/", 1)[-1] or target_id
    attrs = {
        **base,
        "resource_id": target_id,
        "resource_name": name,
        "resource_type": "machine_image" if image else "workload_disk",
        "resource_kind": target_type,
        "cloud_service": SOURCE,
    }
    return f"cloud_resource:{provider}:cwpp:{target_type}:{target_id}", attrs, f"{'image' if image else target_type}: {name}"


def _scan_attributes(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "side_scan_target_id": _text(record, "target_id"),
        "side_scan_target_type": _text(record, "target_type"),
        "side_scan_execution_id": _text(record, "execution_id"),
        "side_scan_package_count": int(record.get("package_count") or 0),
        "side_scan_vulnerability_count": int(record.get("vulnerability_count") or 0),
        "side_scan_packages_truncated": bool(record.get("packages_truncated")),
    }


def _add_package(graph: UnifiedGraph, holder_id: str, pkg: Mapping[str, Any], scan: dict[str, Any]) -> None:
    pkg_dict = dict(pkg)
    pkg_id = _package_node_id(pkg_dict)
    name, version, ecosystem = pkg_dict.get("name", "unknown"), pkg_dict.get("version", ""), pkg_dict.get("ecosystem", "")
    graph.add_node(
        UnifiedNode(
            id=pkg_id,
            entity_type=EntityType.PACKAGE,
            label=f"{name}@{version}" if version else name,
            attributes={
                "version": version,
                "ecosystem": ecosystem,
                "purl": pkg_dict.get("purl", ""),
                "source_package": pkg_dict.get("source_package", ""),
                "canonical_id": canonical_graph_node_id(EntityType.PACKAGE.value, pkg_id),
                "source_ids": source_ids(purl=pkg_dict.get("purl")),
            },
            dimensions=NodeDimensions(ecosystem=ecosystem),
            data_sources=[SOURCE],
        )
    )
    evidence = {**_package_evidence(pkg_dict, SOURCE), **scan}
    graph.add_edge(UnifiedEdge(source=holder_id, target=pkg_id, relationship=RelationshipType.CONTAINS, evidence=evidence))
    for vuln in pkg_dict.get("vulnerabilities") or []:
        if isinstance(vuln, Mapping):
            _add_vuln_node(graph, dict(vuln), pkg_id, SOURCE, evidence)


def _link_launched_instances(graph: UnifiedGraph, image_node_id: str, image_id: str) -> None:
    """Instances inventory recorded as launched from this image depend on it."""
    for node in list(graph.nodes.values()):
        if node.entity_type != EntityType.CLOUD_RESOURCE or node.id == image_node_id:
            continue
        if node.attributes.get("resource_type") == "instance" and node.attributes.get("image_id") == image_id:
            graph.add_edge(
                UnifiedEdge(
                    source=node.id,
                    target=image_node_id,
                    relationship=RelationshipType.DEPENDS_ON,
                    evidence=edge_evidence("cloud-inventory", "recorded", "instance_image_id", image_id=image_id),
                )
            )


def project_side_scan_record(graph: UnifiedGraph, record: Mapping[str, Any]) -> str | None:
    """Project one ``side_scan_results`` record; returns the holder node id."""
    if not _text(record, "provider") or not (_text(record, "target_id") or _text(record, "instance_id")):
        return None
    holder_id, attrs, label = _holder(record)
    scan = _scan_attributes(record)
    provider = _text(record, "provider")
    graph.add_node(
        UnifiedNode(
            id=holder_id,
            entity_type=EntityType.CLOUD_RESOURCE,
            label=label,
            attributes={**attrs, **scan},
            data_sources=[SOURCE],
            dimensions=NodeDimensions(cloud_provider=provider, surface="cwpp"),
        )
    )
    edge_scan = {"side_scan_target_id": scan["side_scan_target_id"], "side_scan_execution_id": scan["side_scan_execution_id"]}
    for pkg in record.get("packages") or []:
        if isinstance(pkg, Mapping) and pkg.get("name"):
            _add_package(graph, holder_id, pkg, {key: value for key, value in edge_scan.items() if value})
    if _text(record, "image_id"):
        _link_launched_instances(graph, holder_id, _text(record, "image_id"))
    return holder_id


def project_side_scan_results(graph: UnifiedGraph, records: Any) -> list[str]:
    """Project every record of a report's ``side_scan_results`` section."""
    if not isinstance(records, list):
        return []
    holders = [project_side_scan_record(graph, record) for record in records if isinstance(record, Mapping)]
    return [holder for holder in holders if holder]
