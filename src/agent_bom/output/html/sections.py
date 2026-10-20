"""HTML section renderers (summary, tables, graph data, CIS, compliance)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.output.finding_views import (
    package_name,
    severity_value,
)
from agent_bom.output.html._common import (
    _SEV_COLOR,
)
from agent_bom.output.html.sections_findings import (
    _CIS_CLOUD_LABELS as _CIS_CLOUD_LABELS,
)
from agent_bom.output.html.sections_findings import (
    _REACH_COLOR as _REACH_COLOR,
)
from agent_bom.output.html.sections_findings import (
    _blast_table as _blast_table,
)
from agent_bom.output.html.sections_findings import (
    _exposure_path_section as _exposure_path_section,
)
from agent_bom.output.html.sections_findings import (
    _non_cve_findings as _non_cve_findings,
)
from agent_bom.output.html.sections_findings import (
    _pager_controls as _pager_controls,
)
from agent_bom.output.html.sections_findings import (
    _policy_findings_section as _policy_findings_section,
)
from agent_bom.output.html.sections_findings import (
    _remediation_list as _remediation_list,
)
from agent_bom.output.html.sections_findings import (
    _vuln_table as _vuln_table,
)
from agent_bom.output.html.sections_findings import (
    _workload_runtime_evidence_hint as _workload_runtime_evidence_hint,
)
from agent_bom.output.html.sections_governance import (
    _BADGE_STYLE as _BADGE_STYLE,
)
from agent_bom.output.html.sections_governance import (
    _CIS_VERDICT_COLOR as _CIS_VERDICT_COLOR,
)
from agent_bom.output.html.sections_governance import (
    _STATUS_BADGE as _STATUS_BADGE,
)
from agent_bom.output.html.sections_governance import (
    _cis_benchmark_section as _cis_benchmark_section,
)
from agent_bom.output.html.sections_governance import (
    _cis_evidence_html as _cis_evidence_html,
)
from agent_bom.output.html.sections_governance import (
    _compliance_section as _compliance_section,
)
from agent_bom.output.html.sections_governance import (
    _enforcement_section as _enforcement_section,
)
from agent_bom.output.html.sections_governance import (
    _trust_assessment_section as _trust_assessment_section,
)
from agent_bom.output.html.sections_inventory import (
    _ai_inventory_section as _ai_inventory_section,
)
from agent_bom.output.html.sections_inventory import (
    _inventory_cards as _inventory_cards,
)
from agent_bom.output.html.sections_inventory import (
    _skill_audit_section as _skill_audit_section,
)
from agent_bom.output.html.sections_summary import (
    _delta_banner as _delta_banner,
)
from agent_bom.output.html.sections_summary import (
    _executive_headline_section as _executive_headline_section,
)
from agent_bom.output.html.sections_summary import (
    _headline_row as _headline_row,
)
from agent_bom.output.html.sections_summary import (
    _scan_outcome_banner as _scan_outcome_banner,
)
from agent_bom.output.html.sections_summary import (
    _summary_cards as _summary_cards,
)
from agent_bom.output.html.sections_summary import (
    _warn_gate_banner as _warn_gate_banner,
)

if TYPE_CHECKING:
    from agent_bom.finding import Finding
    from agent_bom.models import AIBOMReport, BlastRadius


def _chart_data(findings: list["Finding"]) -> str:
    """Build Chart.js dataset JSON for severity donut + blast radius bar chart."""
    from agent_bom.models import Severity

    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for finding in findings:
        sev = severity_value(finding)
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Unassessed findings have no score to chart; they are not drawn as zero bars.
    top10 = sorted((f for f in findings if f.risk_score is not None), key=lambda f: float(f.risk_score or 0.0), reverse=True)[:10]
    blast_labels = [f"{(finding.cve_id or finding.title)[:16]}/{package_name(finding)[:14]}" for finding in top10]
    blast_scores = [round(float(finding.risk_score or 0.0), 2) for finding in top10]
    blast_colors = [_SEV_COLOR.get(severity_value(finding), "#6b7280") for finding in top10]

    from agent_bom.output.graph import _json_for_script
    from agent_bom.security import sanitize_sensitive_payload

    chart = sanitize_sensitive_payload(
        {
            "sev": {
                "labels": [k.capitalize() for k in sev_counts],
                "data": list(sev_counts.values()),
                "colors": [_SEV_COLOR[k] for k in sev_counts],
            },
            "blast": {
                "labels": blast_labels,
                "scores": blast_scores,
                "colors": blast_colors,
            },
        },
        max_str_len=10_000,
    )
    return _json_for_script(chart)


def _cytoscape_elements(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    """Build Cytoscape element list using the shared graph builder."""
    from agent_bom.output.graph import _json_for_script, build_graph_elements, sanitize_graph_elements

    elements, _ = sanitize_graph_elements(build_graph_elements(report, blast_radii, include_cve_nodes=True))
    return _json_for_script(elements, indent=None)


def _attack_flow_elements(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    """Build attack flow element list showing CVE → impact propagation."""
    from agent_bom.output.graph import _json_for_script, build_attack_flow_elements, sanitize_graph_elements

    elements, _ = sanitize_graph_elements(build_attack_flow_elements(report, blast_radii))
    return _json_for_script(elements, indent=None)


def _attack_flow_section(findings: list["Finding"]) -> str:
    """Build the CVE attack flow graph section (only when vulns exist)."""
    if not findings:
        return ""

    total_creds = len({cred for finding in findings for cred in finding.exposed_credentials})
    total_tools = len({tool for finding in findings for tool in finding.exposed_tools})
    total_agents = len({agent for finding in findings for agent in finding.affected_agents})

    return (
        '<section id="attackflow">'
        '<div class="sec-title">&#x1f525; CVE Attack Flow'
        '<span style="font-size:.68rem;font-weight:400;opacity:.5;margin-left:8px">'
        f"{len(findings)} CVEs &#x2192; {total_agents} agents &#x2192; "
        f"{total_creds} credentials &#x2192; {total_tools} tools at risk"
        "</span></div>"
        '<div class="graph-container">'
        '<div id="cyAttack" class="cy-graph"></div>'
        '<div class="graph-controls" style="top:12px;right:12px">'
        '<button class="graph-btn" id="afZoomIn" title="Zoom in">+</button>'
        '<button class="graph-btn" id="afZoomOut" title="Zoom out">&minus;</button>'
        '<button class="graph-btn" id="afFitBtn" title="Fit to view">&#x2922;</button>'
        "</div>"
        "</div>"
        '<div class="legend">'
        '<span><i class="diamond" style="background:#f87171"></i>CVE</span>'
        '<span><i style="background:#dc2626"></i>Vulnerable Package</span>'
        '<span><i style="background:#475569"></i>MCP Server</span>'
        '<span><i style="background:#fbbf24"></i>Credential</span>'
        '<span><i style="background:#818cf8"></i>Tool</span>'
        '<span><i style="background:#3b82f6"></i>Agent</span>'
        "</div>"
        "</section>"
    )
