"""One finding set for the showcase graph and the demo scan job.

The roll-up counts finding nodes in the graph; the overview, ``/v1/posture/counts``
and the findings list count the scan job's finding rows. The showcase graph is
hand-built, so every finding it draws needs a row in the demo scan, and every
row the demo scan reports needs a node in the graph. This module holds both
directions for the parts of the showcase that are not projected from the scan:
the estate's vulnerability occurrences, the hand-built misconfigurations, the
behavioural-drift incidents, the multi-source compute lane, and the MCP
authentication findings the demo scan reports on the hand-built servers.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from agent_bom.demo import DEMO_INVENTORY
from agent_bom.demo_estate.compute_identity_lane import compute_lane_report
from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.enterprise_risk import build_vulnerability_evidence
from agent_bom.demo_estate.id_schemes import showcase_misconfig_id
from agent_bom.demo_estate.showcase_history import refresh_report_finding_summary
from agent_bom.demo_estate.showcase_ids import showcase_server_id
from agent_bom.domain.finding_rehydrate import finding_from_dict
from agent_bom.evidence.finding_node_ids import finding_row_node_id, mcp_audit_node_id, stamp_finding_node_ids
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import fixture_edge_evidence
from agent_bom.graph.governance_overlay import drift_incident_severity
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.inventory import build_agents_from_inventory
from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture

SHOWCASE_FINDING_SOURCE = "demo-showcase"

# (node id, title, severity, affected cloud node, its label)
_SHOWCASE_MISCONFIGURATIONS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        showcase_misconfig_id("pii-public"),
        "S3 bucket customer-pii-prod is publicly readable",
        "high",
        "cloud:pii-bucket",
        "customer-pii-prod (S3)",
    ),
    # Rated as the showcase's own CIS AWS 4.1 check rates this sg-prod ingress.
    (showcase_misconfig_id("sg-open"), "Security group sg-prod allows 0.0.0.0/0 on port 22", "high", "cloud:bastion", "prod-bastion (EC2)"),
)

# (incident id, blueprint / agent label, drift score, violations, violated tool)
SHOWCASE_DRIFT_INCIDENTS: tuple[tuple[str, str, float, int, str], ...] = (
    ("drift-001", "Cursor", 0.78, 14, "run_shell"),
    ("drift-002", "Data Pipeline", 0.41, 5, "execute_sql"),
)


def estate_scan_evidence(tenant_id: str) -> tuple[list[tuple[Any, Finding]], list[Finding]]:
    """The estate's findings for the demo scan: CVE occurrences paired with their blast radii, then the rest.

    Every finding comes from the SAME ``build_estate_findings`` list the graph
    projects, so the findings list, the facets, the exec tiles and every export
    read one derivation.

    The blast radii are not optional. ``output.finding_views.cve_findings``
    resolves the report's CVE array from ``report.blast_radii`` whenever that
    list is non-empty, so an estate with CVE findings but no blast radii lost its
    vulnerability lane between the seeder and the API. That array reuses
    ``report.findings`` only when its CVE findings match the blast radii one for
    one and in order; otherwise it re-keys every row on (advisory, package),
    which collapsed each estate occurrence onto one row bound to a package node
    the graph never draws.
    """
    estate = build_demo_estate(tenant_id=tenant_id)
    findings = list(build_estate_findings(estate))
    kept = {finding.id: finding for finding in findings}
    pairs = [(blast_radius, kept[finding.id]) for blast_radius, finding in build_vulnerability_evidence(estate) if finding.id in kept]
    return pairs, [finding for finding in findings if finding.finding_type is not FindingType.CVE]


def _showcase_misconfiguration_findings() -> list[Finding]:
    return [
        Finding(
            id=f"demo-showcase-{node_id.split(':', 1)[1]}",
            finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
            source=FindingSource.CLOUD_SECURITY,
            asset=Asset(name=label, asset_type="cloud_resource", identifier=asset_node, provider="aws"),
            severity=severity or "unknown",
            title=title,
            node_id=asset_node,
            finding_node_id=node_id,
            evidence={"seed": SHOWCASE_FINDING_SOURCE},
        )
        for node_id, title, severity, asset_node, label in _SHOWCASE_MISCONFIGURATIONS
    ]


def _drift_findings(agent_ids_by_label: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for incident_id, blueprint, score, violations, tool in SHOWCASE_DRIFT_INCIDENTS:
        agent_node = agent_ids_by_label.get(blueprint)
        findings.append(
            Finding(
                id=f"demo-showcase-{incident_id}",
                finding_type=FindingType.TOOL_DRIFT,
                source=FindingSource.PROXY,
                asset=Asset(name=blueprint, asset_type="agent", identifier=agent_node),
                severity=drift_incident_severity(score),
                title=f"drift: {blueprint}",
                description=f"{violations} runtime violation(s) of the approved blueprint, including {tool}",
                node_id=agent_node,
                finding_node_id=f"drift_incident:{incident_id}",
                evidence={"seed": SHOWCASE_FINDING_SOURCE, "incident_id": incident_id, "drift_score": score},
            )
        )
    return findings


def _compute_lane_findings(tenant_id: str) -> list[Finding]:
    """The lane's findings as the scan reports them, bound to the nodes the graph builds."""
    report = compute_lane_report()
    lane = build_unified_graph_from_report(report, scan_id="compute-lane", tenant_id=tenant_id)
    asset_of = {edge.target: edge.source for edge in lane.edges if edge.relationship == RelationshipType.VULNERABLE_TO}
    findings: list[Finding] = []
    for raw in report["findings"]:
        finding = finding_from_dict(raw)
        if finding is None:
            continue
        finding.finding_node_id = finding_row_node_id(raw)
        finding.node_id = asset_of.get(finding.finding_node_id or "")
        findings.append(finding)
    return findings


def append_showcase_graph_findings(report: dict[str, Any], *, tenant_id: str, agent_ids_by_label: dict[str, str]) -> None:
    """Report every finding the showcase graph draws that the scan does not produce.

    Appended after serialization: the compute lane's OS CVEs have no package
    blast radius, and a CVE finding without one would make the report re-derive
    every CVE row from its blast radius instead of reusing the paired findings.
    """
    findings = [*_showcase_misconfiguration_findings(), *_drift_findings(agent_ids_by_label), *_compute_lane_findings(tenant_id)]
    observed_at = str(report.get("generated_at") or "")
    for finding in findings:
        finding.first_seen = finding.first_seen or observed_at or None
    report["findings"] = [*(report.get("findings") or []), *stamp_finding_node_ids([finding.to_dict() for finding in findings])]
    refresh_report_finding_summary(report)


def bind_mcp_auth_findings(findings: list[Finding], servers: Iterable[str]) -> list[Finding]:
    """Bind MCP authentication findings to the hand-built server node they name."""
    known = set(servers)
    for finding in findings:
        if finding.source is FindingSource.MCP_SCAN and finding.asset.name in known:
            finding.node_id = showcase_server_id(finding.asset.name)
            finding.finding_node_id = mcp_audit_node_id(finding.id)
    return findings


def project_mcp_auth_findings(graph: UnifiedGraph, findings: list[Finding]) -> None:
    """Draw the bound MCP authentication findings under their server nodes."""
    for finding in findings:
        server_node = finding.node_id or ""
        if not finding.finding_node_id or server_node not in graph.nodes:
            continue
        node_id = finding.finding_node_id
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.MISCONFIGURATION,
                label=finding.title,
                severity=(finding.severity or "unknown").lower(),
                attributes={"finding_id": finding.id, "finding_source": "MCP_SCAN"},
                data_sources=["mcp-audit"],
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=server_node,
                target=node_id,
                relationship=RelationshipType.VULNERABLE_TO,
                evidence=fixture_edge_evidence(RelationshipType.VULNERABLE_TO, SHOWCASE_FINDING_SOURCE, None),
            )
        )


def demo_mcp_auth_findings() -> list[Finding]:
    """The MCP authentication findings the demo scan reports, from the same inventory."""
    return evaluate_mcp_auth_posture(build_agents_from_inventory(DEMO_INVENTORY, "agent-bom --demo"))


__all__ = [
    "SHOWCASE_DRIFT_INCIDENTS",
    "append_showcase_graph_findings",
    "bind_mcp_auth_findings",
    "demo_mcp_auth_findings",
    "estate_scan_evidence",
    "project_mcp_auth_findings",
]
