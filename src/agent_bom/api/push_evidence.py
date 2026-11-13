"""Server-side trust boundary for pushed scan reports."""

from __future__ import annotations

from typing import cast

from agent_bom.api.audit_log import log_action
from agent_bom.api.finding_collection import collect_scan_findings
from agent_bom.api.models import PushPayload, ScanJob, ScanRequest
from agent_bom.api.posture_recompute import compute_posture_scorecard_from_result
from agent_bom.api.push_models import normalize_push_coverage
from agent_bom.domain.mcp_model import server_dict_counts_as_mcp_server
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.output.json_fmt import _build_finding_summary
from agent_bom.output.report_compaction import compact_report_sections
from agent_bom.security import (
    sanitize_command_args,
    sanitize_env_vars,
    sanitize_security_warnings,
    sanitize_sensitive_payload,
    sanitize_text,
    sanitize_url,
)


def _entity_names(values: object) -> list[str]:
    """Coerce a pushed name list to ``list[str]``, reading ``name`` or ``id`` from objects."""
    names: list[str] = []
    for value in values if isinstance(values, list) else []:
        if isinstance(value, dict):
            value = value.get("name") or value.get("id")
        if isinstance(value, str) and value.strip():
            names.append(value.strip())
    return names


def _normalize_blast_row(row: object) -> object:
    if not isinstance(row, dict):
        return row
    normalized = dict(row)
    for field in ("affected_servers", "affected_agents"):
        if field in normalized:
            normalized[field] = _entity_names(normalized[field])
    return normalized


def normalize_pushed_report(body: PushPayload, *, fallback_scan_id: str) -> dict:
    """Coerce pushed payloads onto the canonical scan report contract.

    The main scan pipeline emits `blast_radius` and agent `type`, while some
    push clients still send `blast_radii` and `agent_type`. Normalizing here
    keeps graph persistence, UI pages, and downstream exporters aligned.
    """
    report = cast(dict, sanitize_sensitive_payload(compact_report_sections(body.model_dump())))
    blast_radius = report.get("blast_radius") or report.get("blast_radii") or []
    report["blast_radius"] = [_normalize_blast_row(row) for row in blast_radius]
    report = compact_report_sections(report)
    report["scan_id"] = str(report.get("scan_id") or fallback_scan_id)
    label_demo_report(report)

    normalized_agents: list[dict] = []
    for raw_agent in report.get("agents", []):
        agent = dict(raw_agent)
        agent_type = str(agent.get("type") or agent.get("agent_type") or "").strip()
        if agent_type:
            agent["type"] = agent_type
            agent["agent_type"] = agent_type
        sanitized_servers: list[dict] = []
        for raw_server in agent.get("mcp_servers", []) or agent.get("servers", []) or []:
            if not isinstance(raw_server, dict):
                continue
            server = dict(raw_server)
            server["command"] = sanitize_text(server.get("command", ""), max_len=200)
            server["args"] = sanitize_command_args(list(server.get("args", []) or []))
            server["url"] = sanitize_url(str(server.get("url") or "")) if server.get("url") else None
            server["env"] = sanitize_env_vars(dict(server.get("env", {}) or {}))
            server["security_warnings"] = sanitize_security_warnings(list(server.get("security_warnings", []) or []))
            server["security_intelligence"] = [
                sanitize_security_intelligence_entry(item)
                for item in (server.get("security_intelligence", []) or [])
                if isinstance(item, dict)
            ]
            sanitized_servers.append(server)
        agent["mcp_servers"] = sanitized_servers
        if "servers" in agent:
            agent["servers"] = sanitized_servers
        normalized_agents.append(agent)
    report["agents"] = normalized_agents
    if (body.target_scope or "summary" in body.model_fields_set) and not body.model_fields_set.intersection(
        {"agents", "blast_radius", "blast_radii", "findings", "endpoint_inventory"}
    ):
        report.setdefault("warnings", []).append(
            "Pushed report contains no supported evidence rows; summary-only data cannot establish coverage."
        )
    report = normalize_push_coverage(report, source_id=body.source_id, target_scope=body.target_scope)
    derive_push_summary(report)
    # A producer grade is not a server-computed posture assessment: replace it
    # with the scorecard derived here from the retained evidence.
    scorecard = compute_posture_scorecard_from_result(report).to_dict()
    report["posture_scorecard"] = scorecard
    report["posture_grade"] = scorecard["grade"]
    report["posture_grade_label"] = scorecard["grade_label"]
    return report


def label_demo_report(report: dict) -> None:
    """Mark a pushed sample report as demo data, including reports from older clients.

    Clients before 0.115.0 sent ``--demo`` scans without a ``demo`` source; the
    bundled demo advisory DB still identifies them, so the UI banner and the
    demo-data guards keep sample agents from passing as real inventory.
    """
    sources = report.get("scan_sources")
    sources = [str(source) for source in sources] if isinstance(sources, list) else []
    freshness = report.get("vuln_data_freshness")
    bundled_demo = isinstance(freshness, dict) and freshness.get("mode") == "bundled-demo"
    if bundled_demo and "demo" not in sources:
        sources.append("demo")
    if sources or "scan_sources" in report:
        report["scan_sources"] = sources


def derive_push_summary(report: dict) -> None:
    """Count retained evidence using the same deduplication as the findings API.

    Current runtime enrichment and approved suppressions are read-time state;
    they must not rewrite the stored observation or establish clean evidence.
    """
    job = ScanJob(job_id=report["scan_id"], created_at="", request=ScanRequest(), result=report)
    findings = collect_scan_findings(job)
    finding_summary = _build_finding_summary(findings)
    agents = report.get("agents") or []
    servers = [server for agent in agents for server in agent.get("mcp_servers", []) or []]
    packages = [package for server in servers for package in server.get("packages", []) or [] if isinstance(package, dict)]
    package_keys = {(str(p.get("name") or ""), str(p.get("version") or ""), str(p.get("ecosystem") or "")) for p in packages}
    vuln_ids = {str(f.get("vulnerability_id") or f.get("cve_id")) for f in findings if f.get("vulnerability_id") or f.get("cve_id")}
    report["summary"] = {
        "total_agents": len(agents),
        "total_mcp_servers": sum(1 for server in servers if isinstance(server, dict) and server_dict_counts_as_mcp_server(server)),
        "total_packages": sum(
            len(server.get("packages") or []) for server in servers if isinstance(server, dict) and not server.get("package_binding_of")
        ),
        "unique_packages": len(package_keys),
        "total_vulnerabilities": len(vuln_ids),
        "total_findings": len(findings),
        "critical_findings": finding_summary["by_severity"]["critical"],
        "critical_unified_findings": finding_summary["by_severity"]["critical"],
        "high_unified_findings": finding_summary["by_severity"]["high"],
        "coverage_warnings": report.get("coverage_warnings", []),
    }
    report["finding_summary"] = finding_summary


def audit_push_admission(job: ScanJob, report: dict, *, actor: str, request_hash: str) -> None:
    """Fail closed before writes; admission is explicitly not a commit receipt.

    Audit and evidence stores do not share a transaction. Retain this attempt
    even when a subsequent write fails; use its job id to inspect the result.
    Idempotent replays bypass admission and cannot manufacture another event.
    """
    log_action(
        "results.push.accepted",
        actor=actor,
        resource=job.job_id,
        tenant_id=job.tenant_id,
        job_id=job.job_id,
        source_id=job.source_id or "",
        scan_id=str(report.get("scan_id") or job.job_id),
        evidence_id=str(report.get("target_scope") or "unscoped"),
        payload_sha256=request_hash,
        outcome="accepted",
    )
