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

from agent_bom.demo_advisories import DEMO_EPSS_SOURCE, DEMO_HOST_ADVISORIES, DemoAdvisory, demo_epss
from agent_bom.graph.asset_canonicalize import ANALYZER
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import fixture_edge_evidence
from agent_bom.graph.types import RelationshipType
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability

DEMO_COMPUTE_ACCOUNT = "111122223333"
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


def _sensor_host_asset(index: int) -> dict[str, Any]:
    """A runtime sensor names the host only by host name."""
    return {
        "name": _hostname(index),
        "asset_type": "cloud_resource",
        "resource_type": "host",
        "identifier": _hostname(index),
        "provider": "sensor",
    }


def _host_risk_score(advisory: DemoAdvisory, on_agent_path: bool) -> float:
    """Score the occurrence with the same scorer every package CVE goes through."""
    blast_radius = BlastRadius(
        vulnerability=Vulnerability(
            id=advisory.vuln_id,
            summary=advisory.summary,
            severity=Severity(advisory.severity),
            cvss_score=advisory.cvss_score,
            is_kev=advisory.is_kev,
            epss_score=demo_epss(advisory),
        ),
        package=Package(name=advisory.package, version=advisory.sample_version, ecosystem=advisory.ecosystem),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        graph_reachable=True if on_agent_path else None,
    )
    return round(blast_radius.calculate_risk_score(), 2)


def _vm_cve(index: int) -> dict[str, Any]:
    """An OS-package CVE an agentless scanner reported on a lane VM.

    VM 0 schedules the in-cluster MCP server's pod, so its CVE sits on a modeled
    agent → server → pod → VM path (``likely``, structural only). VM 1 has no
    such path and no other reachability evidence, so its verdict is ``unknown``.
    """
    advisory = DEMO_HOST_ADVISORIES[index % len(DEMO_HOST_ADVISORIES)]
    installed = advisory.sample_version
    on_agent_path = index == 0
    return {
        "risk_score": _host_risk_score(advisory, on_agent_path),
        "id": f"demo-compute-cve-{index:02d}",
        "finding_type": "CVE",
        "cve_id": advisory.vuln_id,
        "source": "CLOUD_SECURITY",
        "severity": advisory.severity,
        "cvss_score": advisory.cvss_score,
        "cwe_ids": [advisory.cwe],
        "title": f"{advisory.vuln_id}: {advisory.package}@{installed}",
        "description": advisory.summary,
        "fixed_version": advisory.fixed,
        "remediation_guidance": f"Upgrade {advisory.package} to {advisory.fixed}.",
        "epss_score": demo_epss(advisory),
        "is_kev": advisory.is_kev,
        "reachability": "likely" if on_agent_path else "unknown",
        "graph_reachable": True if on_agent_path else None,
        "evidence": {
            "package_name": advisory.package,
            "package_version": installed,
            "ecosystem": advisory.ecosystem,
            "configuration": {
                "setting": f"{advisory.package} package version",
                "observed": f"{advisory.package}@{installed}",
                "expected": f"{advisory.package}>={advisory.fixed}",
            },
            "advisory_source": advisory.source,
            "epss_source": DEMO_EPSS_SOURCE,
            "reachability_basis": ["graph_path"] if on_agent_path else ["insufficient_evidence"],
        },
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
                    "k8s_cloud_account_id": DEMO_COMPUTE_ACCOUNT,
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
            "finding_type": "CLOUD_BEST_PRACTICE_FAIL",
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
            "finding_type": "CLOUD_BEST_PRACTICE_FAIL",
            "source": "EXTERNAL",
            "severity": "low",
            "title": "Host permits execution of unsigned binaries",
            "asset": _sensor_host_asset(index),
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
    lane = build_unified_graph_from_report(
        compute_lane_report(evidence=evidence),
        scan_id=graph.scan_id,
        tenant_id=tenant_id,
        container=UnifiedGraph(scan_id=graph.scan_id, tenant_id=tenant_id, created_at=graph.created_at),
    )
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
