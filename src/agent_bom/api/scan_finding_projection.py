"""Scan finding projection."""

from __future__ import annotations

from typing import Any

from agent_bom.api.finding_collection import collect_scan_findings, merge_finding_representations
from agent_bom.api.finding_read_context import read_once
from agent_bom.api.finding_row_shapes import _normalize_finding_identifiers, _scan_source_labels
from agent_bom.api.finding_suppression import project_current_suppressions
from agent_bom.api.models import ScanJob
from agent_bom.api.scan_graph_view import _effective_reach_lookup as _effective_reach_lookup
from agent_bom.api.scan_snapshot_read import verified_snapshot_findings
from agent_bom.core.reachability import review_only_match
from agent_bom.finding_reach_sources import SERVER_STAMPED_REACH_FIELDS
from agent_bom.finding_runtime_evidence import (
    attach_runtime_evidence_to_finding,
    build_incident_runtime_evidence_index,
    build_tenant_runtime_evidence_index,
    compliance_tags_from_finding_row,
)


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
    from agent_bom.finding_runtime_evidence import compliance_tags_from_finding_row

    row["framework_tags"] = compliance_tags_from_finding_row(row)
    return row


def _iter_scan_findings(job: ScanJob) -> list[dict[str, Any]]:
    result = job.result or {}
    reach: dict[str, dict[str, Any]] | None = None

    def use_reach(value: dict[str, dict[str, Any]] | None) -> None:
        nonlocal reach
        reach = value

    tenant_id = str(getattr(job, "tenant_id", None) or "default")
    runtime_index = read_once(("runtime_events", tenant_id), lambda: build_tenant_runtime_evidence_index(tenant_id))
    incidents = result.get("runtime_incident_feedback")
    incident_index = build_incident_runtime_evidence_index(incidents if isinstance(incidents, list) else [])

    # CWPP runtime/EDR workload evidence (#4158 stage 3): additive, read-only.
    # Only workload-scoped rows are annotated, and only when this tenant actually
    # has runtime signals — an empty index leaves every row untouched, so absence
    # of runtime data is never rendered as a clean workload. Reachability is never
    # invented here.
    from agent_bom.cloud.runtime_workload_evidence import (
        RuntimeWorkloadEvidenceIndex,
        attach_workload_runtime_evidence_to_finding,
    )
    from agent_bom.cloud.runtime_workload_evidence_store import get_runtime_workload_evidence_store

    workload_runtime_index: RuntimeWorkloadEvidenceIndex | None = None
    try:
        _wl_index = read_once(
            ("workload_runtime_events", tenant_id),
            lambda: RuntimeWorkloadEvidenceIndex.from_store(get_runtime_workload_evidence_store(), tenant_id),
        )
        if not _wl_index.is_empty():
            workload_runtime_index = _wl_index
    except Exception:  # noqa: BLE001 - runtime evidence is additive; never break the read path
        workload_runtime_index = None

    def _attach_reach(row: dict[str, Any]) -> dict[str, Any]:
        row.setdefault("framework_tags", compliance_tags_from_finding_row(row))
        # Scan completion is authoritative observation time for scan-spine rows.
        # Do not infer first-seen history from the currently retained job set.
        observed_at = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
        if observed_at is not None:
            row.setdefault("last_observed", observed_at)
        attach_runtime_evidence_to_finding(row, runtime_index, incident_index=incident_index)
        if workload_runtime_index is not None:
            attach_workload_runtime_evidence_to_finding(row, workload_runtime_index)
        return row

    findings = verified_snapshot_findings(
        job, lambda: collect_scan_findings(job, _attach_reach), _attach_reach, merge=merge_finding_representations, use_reach=use_reach
    )
    # Score after representations merge so backfilled CVSS/EPSS/KEV and the
    # merged occurrence's own agents are what the composite sees.
    occurrence_reach = reach if reach is not None else _effective_reach_lookup(job)
    for row in findings:
        _score_occurrence_reach(row, occurrence_reach)
        for key in SERVER_STAMPED_REACH_FIELDS:  # an imported result cannot pre-stamp path sources
            row.pop(key, None)
    return _project_finding_owners_and_suppressions(findings, tenant_id)


def _score_occurrence_reach(row: dict[str, Any], reach: dict[str, dict[str, Any]]) -> None:
    from agent_bom.effective_reach import occurrence_context_for_row, occurrence_score
    from agent_bom.symbol_reach_triage import (
        adjust_effective_reach_breakdown,
        apply_composite_delta,
        band_from_composite,
        symbol_reachability_from_payload,
    )

    if review_only_match(row.get("match_confidence_tier")):
        # An unresolved package match has no verified occurrence to score.
        row.update(effective_reach=None, effective_reach_score=None, effective_reach_band=None, reachability="unknown")
        return
    if row.get("effective_reach_score") is not None and not isinstance(row.get("effective_reach"), dict):
        return  # A producer-supplied composite is authoritative for its own row.
    context = occurrence_context_for_row(reach, row)
    sym = symbol_reachability_from_payload(row)
    if context is not None or any(row.get(key) not in (None, "", False) for key in ("cvss_score", "epss_score", "is_kev", "cisa_kev")):
        breakdown = adjust_effective_reach_breakdown(occurrence_score(row, context).as_breakdown(), sym)
    elif sym:
        composite = apply_composite_delta(0.0, sym)
        breakdown = {"composite": composite, "band": band_from_composite(composite), "symbol_reachability": sym}
    else:
        return
    row["effective_reach"] = breakdown
    row["effective_reach_score"] = breakdown.get("composite")
    row["effective_reach_band"] = breakdown.get("band")


def _project_finding_owners_and_suppressions(findings: list[dict[str, Any]], tenant_id: str) -> list[dict[str, Any]]:
    # Surface the triage assignee as the finding owner (the simple ownership cut).
    # Built once per tenant and matched per row; rows with no triage assignee keep
    # whatever owner the scan spine already set (an explicit None when unassigned,
    # rendered "Unassigned" only in the CLI/UI).
    from agent_bom.api.routes.enterprise import build_tenant_triage_owner_index, triage_owner_for

    owner_index = build_tenant_triage_owner_index(tenant_id)
    for row in findings:
        _normalize_finding_identifiers(row)
        if owner_index:
            raw_asset = row.get("asset")
            asset = raw_asset if isinstance(raw_asset, dict) else {}
            raw_evidence = row.get("evidence")
            evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
            package = str(row.get("package") or row.get("package_name") or evidence.get("package_name") or asset.get("name") or "")
            assignee = triage_owner_for(
                owner_index,
                vuln_id=str(row.get("vulnerability_id") or row.get("cve_id") or ""),
                package=package,
                server_name=str(row.get("server_name") or ""),
            )
            if assignee:
                row["owner"] = assignee
    return project_current_suppressions(findings, tenant_id)
