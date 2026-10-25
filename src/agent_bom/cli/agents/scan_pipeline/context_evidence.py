"""Copy discovery-time evidence from the scan context onto a report.

Both the full report and the partial report an incomplete scan exits with go
through here, so a scan whose vulnerability data was unavailable still carries
the AI inventory, framework agents, project inventory and source findings that
discovery already collected.
"""

from __future__ import annotations

from typing import Any


def attach_context_evidence(report: Any, ctx: Any) -> None:
    """Attach skill, trust, prompt, enforcement, SAST and inventory evidence from *ctx*."""
    if ctx.skill_audit_data:
        report.skill_audit_data = ctx.skill_audit_data
        from agent_bom.parsers.skill_audit import replace_skill_findings

        replace_skill_findings(report, ctx.skill_audit_data)
    if ctx.trust_assessment_data:
        report.trust_assessment_data = ctx.trust_assessment_data
    if ctx.prompt_scan_data:
        report.prompt_scan_data = ctx.prompt_scan_data
        from agent_bom.parsers.prompt_scanner import prompt_scan_data_to_findings

        report.findings.extend(prompt_scan_data_to_findings(ctx.prompt_scan_data))
    if ctx.external_findings:
        known_ids = {f.id for f in report.findings}
        report.findings.extend(f for f in ctx.external_findings if f.id not in known_ids)
    if ctx.enforcement_data:
        report.enforcement_data = ctx.enforcement_data
    if ctx.sast_data:
        report.sast_data = ctx.sast_data
    if ctx.ai_inventory_data:
        report.ai_inventory_data = ctx.ai_inventory_data
    if ctx.project_inventory_data:
        report.project_inventory_data = ctx.project_inventory_data
    if ctx.repo_trust_data:
        report.repo_trust_data = ctx.repo_trust_data
    if ctx.model_hash_verification_data:
        report.model_hash_verification_data = ctx.model_hash_verification_data
