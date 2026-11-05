"""One blast-radius item as a finding row, with no tenant enrichment."""

from __future__ import annotations

from typing import Any

from agent_bom.api.finding_row_shapes import _scan_source_labels
from agent_bom.api.models import ScanJob
from agent_bom.evidence.compliance_row_tags import compliance_tags_from_finding_row


def _operator_vex_overlay(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "suppressed": True,
        "actionable": False,
        "suppression_state": "vex",
        "suppression_reason": item.get("suppression_reason") or f"vex: {item.get('vex_justification') or item.get('vex_status')}",
        "unsuppressed_risk_score": item.get("unsuppressed_risk_score"),
        "risk_score": 0.0,
    }


def _finding_from_blast_radius(item: dict[str, Any], job: ScanJob) -> dict[str, Any]:
    vulnerability_id = item.get("vulnerability_id") or item.get("id") or ""
    package = item.get("package") or item.get("package_name") or ""
    vex_status = item.get("vex_status")
    risk_score = item.get("risk_score", item.get("blast_score", 0))
    vex_suppressed = item.get("vex_source") == "operator" and vex_status in {"not_affected", "fixed"}
    canonical_id = item.get("canonical_id") or item.get("finding_id")
    row = {
        "id": canonical_id or f"{vulnerability_id}:{package}",
        "canonical_id": canonical_id,
        "asset": item.get("asset"),
        "vulnerability_id": vulnerability_id,
        "package": package,
        "severity": (item.get("severity") or "unknown").lower(),
        "source": "blast_radius",
        "scan_id": str((job.result or {}).get("scan_id") or job.job_id),
        "scan_sources": _scan_source_labels(job),
        "affected_agents": item.get("affected_agents", []),
        "affected_servers": item.get("affected_servers", []),
        "exposed_credentials": item.get("exposed_credentials", []),
        "exposed_tools": item.get("exposed_tools", []),
        "phantom_tools": item.get("phantom_tools", []),
        "risk_score": risk_score,
        "cvss_score": item.get("cvss_score"),
        "epss_score": item.get("epss_score"),
        "upstream_ids": item.get("upstream_ids"),
        "epss_cve_id": item.get("epss_cve_id"),
        "kev_cve_id": item.get("kev_cve_id"),
        "attack_vector_summary": item.get("attack_vector_summary"),
        "impact_category": item.get("impact_category"),
        "ai_risk_context": item.get("ai_risk_context"),
        "fixed_version": item.get("fixed_version"),
        "is_kev": bool(item.get("is_kev") or item.get("cisa_kev")),
        "reachability": item.get("reachability"),
        "graph_reachable": item.get("graph_reachable"),
        "graph_min_hop_distance": item.get("graph_min_hop_distance"),
        "graph_reachable_from_agents": item.get("graph_reachable_from_agents", []),
        "symbol_reachability": item.get("symbol_reachability"),
        "reachable_affected_symbols": item.get("reachable_affected_symbols", []),
        "symbol_reachability_reason": item.get("symbol_reachability_reason"),
        "runtime_dependency_chain": item.get("runtime_dependency_chain", []),
        "match_confidence_tier": item.get("match_confidence_tier"),
        "vex_status": vex_status,
        "vex_justification": item.get("vex_justification"),
        "vex_source": item.get("vex_source"),
        "vex_statement_id": item.get("vex_statement_id"),
        "vex_suppressed": vex_suppressed,
        **(_operator_vex_overlay(item) if vex_suppressed else {}),
        "compliance_tags": item.get("compliance_tags"),
    }
    for tag_field in (
        "owasp_tags",
        "atlas_tags",
        "attack_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
        "cmmc_tags",
        "nist_800_53_tags",
        "fedramp_tags",
        "pci_dss_tags",
    ):
        if tag_field in item:
            row[tag_field] = item.get(tag_field) or []
    row["framework_tags"] = compliance_tags_from_finding_row(row)
    return row
