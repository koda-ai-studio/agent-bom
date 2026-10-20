"""Ordered graph analysis: identity, topology, final paths, then risk projections.

Each optional analysis preserves the existing failure isolation. Path fusion
runs after all topology producers; ASPM and cost consume the final paths.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from agent_bom.graph.asset_canonicalize import canonicalize_assets
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.credential_findings import project_credential_findings
from agent_bom.graph.edge_freshness import stamp_edge_freshness
from agent_bom.graph.finding_row_projection import project_finding_rows
from agent_bom.graph.interaction_risk_ids import bind_interaction_risk_agent_ids
from agent_bom.graph.provider_inheritance import inherit_cloud_provider
from agent_bom.graph.relationship_contract import audit_graph_contract
from agent_bom.graph.storage_integration_correlation import correlate_storage_integrations

_logger = logging.getLogger("agent_bom.graph.builder")
ReportOverlay = Callable[[UnifiedGraph, Mapping[str, Any]], None]


@dataclass(frozen=True)
class GraphAnalysisPorts:
    runtime_evidence: ReportOverlay
    repo_structure: ReportOverlay
    ast_tool: ReportOverlay
    code_graph: ReportOverlay
    repo_trust: ReportOverlay
    ci_graph: ReportOverlay
    agent_reach_risk: Callable[[UnifiedGraph], None]
    aspm: ReportOverlay
    cost: ReportOverlay


def apply_build_analysis(graph: UnifiedGraph, report_json: dict[str, Any], ports: GraphAnalysisPorts) -> None:
    _identity_analysis(graph, report_json)
    _topology_analysis(graph, report_json, ports)
    # Path receipts read edge freshness, so stamp it before fusion annotates.
    _stamp_freshness(graph)
    _risk_analysis(graph, report_json, ports)
    # Assessments must not feed back into the topology analysis that produced them.
    project_credential_findings(graph, report_json.get("findings"))
    project_finding_rows(graph, report_json.get("findings"))
    bind_interaction_risk_agent_ids(graph)
    # Assets a finding row named for the first time join the asset they observe.
    canonicalize_assets(graph)
    # Merged assets inherit the provider their recorded host or scope proves.
    inherit_cloud_provider(graph)
    # Edges the assessment projections added after fusion.
    _stamp_freshness(graph)
    audit_graph_contract(graph)


def _stamp_freshness(graph: UnifiedGraph) -> None:
    try:
        stamp_edge_freshness(graph)
    except Exception:  # noqa: BLE001 - missing freshness leaves receipts unknown, never fails the build
        _logger.warning("edge freshness stamping failed", exc_info=True)


def _identity_analysis(graph: UnifiedGraph, report_json: dict[str, Any]) -> None:
    try:
        from agent_bom.graph.nhi_overlay import apply_nhi_overlay_from_report

        apply_nhi_overlay_from_report(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("NHI discovery overlay failed", exc_info=True)

    try:
        from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay

        apply_cnapp_overlay(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("CNAPP overlay failed", exc_info=True)

    # Pure attribute joins on recorded identifiers; nothing here can fail on partial data.
    correlate_storage_integrations(graph)

    try:
        from agent_bom.graph.effective_permissions import apply_effective_permissions

        apply_effective_permissions(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("effective-permissions overlay failed", exc_info=True)

    try:
        from agent_bom.graph.nhi_governance import apply_nhi_governance_with_findings

        _nhi_summary, _nhi_findings = apply_nhi_governance_with_findings(graph)
        # Stash the materialized findings on the graph so the shared scan callers
        # (CLI scan_cmd + API pipeline) can route them into the unified finding
        # stream. The node-annotation side effects are identical to the previous
        # apply_nhi_governance(graph) call; only the findings are new.
        graph.nhi_governance_findings = _nhi_findings
    except Exception:  # noqa: BLE001
        _logger.warning("NHI governance overlay failed", exc_info=True)

    try:
        from agent_bom.a2a_auth_posture import annotate_graph_a2a_auth_from_report

        annotate_graph_a2a_auth_from_report(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("A2A auth posture overlay failed", exc_info=True)

    try:
        from agent_bom.mcp_auth_posture import annotate_graph_mcp_auth_from_report

        annotate_graph_mcp_auth_from_report(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("MCP auth posture overlay failed", exc_info=True)


def _topology_analysis(graph: UnifiedGraph, report_json: dict[str, Any], ports: GraphAnalysisPorts) -> None:
    try:
        ports.runtime_evidence(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("runtime evidence overlay failed", exc_info=True)

    try:
        ports.repo_structure(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("repo-structure overlay failed", exc_info=True)

    try:
        ports.ast_tool(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("AST tool overlay failed", exc_info=True)

    try:
        ports.code_graph(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("code-graph overlay failed", exc_info=True)

    try:
        ports.repo_trust(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("repo-trust overlay failed", exc_info=True)

    try:
        ports.ci_graph(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("ci-graph overlay failed", exc_info=True)

    try:
        from agent_bom.graph.endpoint_overlay import apply_endpoint_inventory_overlay

        apply_endpoint_inventory_overlay(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("endpoint-inventory overlay failed", exc_info=True)


def _risk_analysis(graph: UnifiedGraph, report_json: dict[str, Any], ports: GraphAnalysisPorts) -> None:
    try:
        from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion

        apply_attack_path_fusion(graph)
    except Exception:  # noqa: BLE001
        from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus

        graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(
            status=GraphAnalysisState.FAILED,
            reason_codes=("analysis_error",),
            observed={"node_count": len(graph.nodes), "result_count": 0},
        )
        _logger.warning("attack-path fusion failed: analysis_error")

    try:
        from agent_bom.graph.attack_path_mitre import apply_attack_path_technique_mappings

        apply_attack_path_technique_mappings(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("attack-path technique mapping failed: analysis_error")

    try:
        ports.agent_reach_risk(graph)
    except Exception:  # noqa: BLE001
        _logger.warning("agent reach risk failed: analysis_error")

    try:
        ports.aspm(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("ASPM overlay failed", exc_info=True)

    try:
        ports.cost(graph, report_json)
    except Exception:  # noqa: BLE001
        _logger.warning("cost overlay failed", exc_info=True)
