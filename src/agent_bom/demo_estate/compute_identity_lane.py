"""Seeded multi-source compute lane: one VM, many sources, one graph node.

An in-cluster MCP server runs in a pod scheduled on one VM, and two VMs carry
an OS CVE, so paths run agent → server → pod → VM → CVE and VM → CVE.

Every VM in this lane is reported the way a real estate reports it: the
inventory scan lists the instance, CloudTrail records an assumed role stopping
it by ARN, a workload side scan names it as its target and a posture finding
names it by ARN. Each source mints its own node id; asset canonicalization
merges them. A few runtime-sensor findings name hosts only by host name — the
same host name an inventory VM carries — and must stay separate, proposed only
as a reviewable candidate.

All identifiers are synthetic: the account, VPC, instance ids, host names and
ARNs are fabricated and never correspond to a real estate.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.asset_canonicalize import ANALYZER
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import fixture_edge_evidence
from agent_bom.graph.types import RelationshipType

DEMO_COMPUTE_ACCOUNT = "210987654321"
DEMO_COMPUTE_REGION = "us-east-1"
DEMO_COMPUTE_VMS = 12
DEMO_HOSTNAME_DECOYS = 3
_VPC = "vpc-0demo0compute0lane"


def _instance_id(index: int) -> str:
    return f"i-0de{index:014x}"


def _hostname(index: int) -> str:
    return f"ip-10-42-0-{10 + index}.ec2.internal"


def _side_scan_target(index: int) -> dict[str, Any]:
    return {
        "target_id": _instance_id(index),
        "target_type": "instance",
        "provider": "aws",
        "account_id": DEMO_COMPUTE_ACCOUNT,
        "location": DEMO_COMPUTE_REGION,
        "status": "eligible",
    }


def _vm_cve(index: int) -> dict[str, Any]:
    """An OS-package CVE an agentless scanner reported on a lane VM."""
    return {
        "id": f"demo-compute-cve-{index:02d}",
        "finding_type": "CVE",
        "cve_id": ("CVE-2024-6387", "CVE-2023-38408")[index % 2],
        "source": "CLOUD_SECURITY",
        "severity": "high",
        "title": ("OpenSSH signal handler race", "OpenSSH ssh-agent PKCS#11 remote code execution")[index % 2],
        "asset": {"name": f"compute-{index:02d}", "asset_type": "cloud_resource", "identifier": demo_compute_arn(index), "provider": "aws"},
    }


def _hosted_mcp_agent() -> dict[str, Any]:
    """An in-cluster MCP server whose pod is scheduled on lane VM 0."""
    return {
        "name": "cluster-ops-agent",
        "type": "custom",
        "source": "kubernetes",
        "mcp_servers": [
            {
                "name": "ops/runbook-mcp/server",
                "url": "http://runbook-mcp.ops.svc.cluster.local:8000",
                "transport": "sse",
                "connection_metadata": {
                    "k8s_pod_uid": "0d3e5f7a-1b2c-4d5e-8f90-a1b2c3d4e5f6",
                    "k8s_pod": "runbook-mcp",
                    "k8s_namespace": "ops",
                    "k8s_cluster": "demo-compute",
                    "k8s_node": _hostname(0),
                    "k8s_node_provider_id": f"aws:///{DEMO_COMPUTE_REGION}a/{_instance_id(0)}",
                },
            }
        ],
    }


def demo_compute_arn(index: int) -> str:
    return f"arn:aws:ec2:{DEMO_COMPUTE_REGION}:{DEMO_COMPUTE_ACCOUNT}:instance/{_instance_id(index)}"


def compute_lane_report(*, vms: int = DEMO_COMPUTE_VMS, decoys: int = DEMO_HOSTNAME_DECOYS, evidence: bool = True) -> dict[str, Any]:
    """Report sections a scan of the lane would carry; graph projection does the rest.

    ``evidence=False`` is the pre-window baseline: inventory only, before the
    audit trail, side scan and findings of the collection window arrived.
    """
    instances = [
        {
            "instance_id": _instance_id(index),
            "name": f"compute-{index:02d}",
            "region": DEMO_COMPUTE_REGION,
            "instance_type": "m6i.large",
            "state": "running",
            "vpc_id": _VPC,
            "private_ip": f"10.42.0.{10 + index}",
            "private_dns_name": _hostname(index),
        }
        for index in range(vms)
    ]
    side_scan = [_side_scan_target(index) for index in range(vms)]
    audit = [
        {
            "principal": "compute-operator",
            "principal_arn": f"arn:aws:sts::{DEMO_COMPUTE_ACCOUNT}:assumed-role/compute-operator/demo-session",
            "resource": demo_compute_arn(index),
            "action": "StopInstances" if index % 2 else "ModifyInstanceAttribute",
            "relationship": "invoked",
            "count": 1 + index % 3,
            "last_seen": "2026-08-03T18:00:00Z",
        }
        for index in range(vms)
    ]
    findings: list[dict[str, Any]] = [
        {
            "id": f"demo-compute-imds-{index:02d}",
            "finding_type": "CLOUD_MISCONFIGURATION",
            "source": "CLOUD_SECURITY",
            "severity": "medium",
            "title": "Instance metadata service v1 is enabled",
            "asset": {
                "name": f"compute-{index:02d}",
                "asset_type": "cloud_resource",
                "identifier": demo_compute_arn(index),
                "provider": "aws",
            },
        }
        for index in range(vms)
    ]
    findings.extend(
        {
            "id": f"demo-sensor-host-{index:02d}",
            "finding_type": "CLOUD_MISCONFIGURATION",
            "source": "EXTERNAL",
            "severity": "low",
            "title": "Unsigned binary executed",
            "asset": {
                "name": _hostname(index),
                "asset_type": "cloud_resource",
                "resource_type": "host",
                "identifier": _hostname(index),
                "provider": "sensor",
            },
        }
        for index in range(min(decoys, vms))
    )
    inventory = {
        "status": "ok",
        "provider": "aws",
        "account_id": DEMO_COMPUTE_ACCOUNT,
        "region": DEMO_COMPUTE_REGION,
        "instances": instances,
    }
    if not evidence:
        return {"cloud_inventory": inventory}
    findings.extend(_vm_cve(index) for index in range(min(2, vms)))
    return {
        "agents": [_hosted_mcp_agent()],
        "cloud_inventory": {**inventory, "side_scan_targets": side_scan},
        "cloud_audit_trail": {"status": "ok", "provider": "aws", "account": DEMO_COMPUTE_ACCOUNT, "behavioral_edges": audit},
        "findings": findings,
    }


def project_compute_lane(graph: UnifiedGraph, *, tenant_id: str, evidence: bool, org_node_id: str = "") -> None:
    """Build the lane through the real graph builder and add it to a showcase snapshot."""
    lane = build_unified_graph_from_report(compute_lane_report(evidence=evidence), scan_id=graph.scan_id, tenant_id=tenant_id)
    for node in lane.nodes.values():
        graph.add_node(node)
    for edge in lane.edges:
        graph.add_edge(edge)
    if ANALYZER in lane.analysis_status:
        graph.analysis_status[ANALYZER] = lane.analysis_status[ANALYZER]
    account_node_id = f"account:aws:{DEMO_COMPUTE_ACCOUNT}"
    if org_node_id and org_node_id in graph.nodes and account_node_id in graph.nodes:
        graph.add_edge(
            UnifiedEdge(
                source=org_node_id,
                target=account_node_id,
                relationship=RelationshipType.CONTAINS,
                evidence=fixture_edge_evidence(RelationshipType.CONTAINS, "demo-estate", None),
            )
        )
