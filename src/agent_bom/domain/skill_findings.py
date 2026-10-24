"""Serialized skill-audit results as unified findings.

Kept free of scanner imports so the graph builder can key skill-audit nodes by
the same finding ids the report carries.
"""

from __future__ import annotations

from pathlib import Path


def _risk_score(severity: str) -> float:
    return {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }.get(str(severity or "").lower(), 1.0)


def _finding_type_for_skill_category(category: str):
    """Map skill-audit categories onto the unified Finding taxonomy.

    Behavioral / package / server findings stay ``SKILL_RISK`` so the skill
    lane keeps a single rule id in SARIF/exports. Only curated MCP blocklist
    hits cross-walk to ``MCP_BLOCKLIST`` (same policy signal as MCP scan).
    """
    from agent_bom.finding import FindingType

    normalized = str(category or "").lower()
    if normalized == "mcp_blocklist":
        return FindingType.MCP_BLOCKLIST
    return FindingType.SKILL_RISK


def skill_audit_data_to_findings(skill_audit: dict) -> list:
    """Convert serialized skill-audit data into the unified Finding stream.

    Mirrors ``prompt_scan_data_to_findings`` so main-scan / API reports carry
    ``FindingType.SKILL_RISK`` (and MCP blocklist hits) instead of leaving
    skill results only in the ``skill_audit_data`` sidecar.
    """
    from agent_bom.compliance_hub import apply_hub_classification
    from agent_bom.finding import Asset, Finding, FindingSource
    from agent_bom.security import sanitize_path_label

    if not isinstance(skill_audit, dict):
        return []

    unified = []
    for item in skill_audit.get("findings") or []:
        if not isinstance(item, dict):
            continue
        source_file = str(item.get("source_file") or "")
        category = str(item.get("category") or "skill_risk")
        severity = str(item.get("ai_adjusted_severity") or item.get("severity") or "unknown").lower()
        if severity == "false_positive":
            continue
        title = str(item.get("title") or "Skill security finding")
        asset_name = str(item.get("server") or item.get("package") or "") or (Path(source_file).name if source_file else "skill")
        asset_type = "mcp_server" if item.get("server") else ("package" if item.get("package") else "skill_file")
        identifier = item.get("server") or item.get("package") or source_file or None
        unified.append(
            apply_hub_classification(
                Finding(
                    finding_type=_finding_type_for_skill_category(category),
                    source=FindingSource.SKILL,
                    asset=Asset(
                        name=asset_name,
                        asset_type=asset_type,
                        identifier=str(identifier) if identifier else None,
                        location=_safe_relative_path(item.get("source_path"))
                        or (sanitize_path_label(source_file) if source_file else None),
                    ),
                    severity=severity,
                    title=title,
                    description=_without_host_path(str(item.get("detail") or title), source_file),
                    remediation_guidance=str(item.get("recommendation") or "") or None,
                    owasp_tags=["LLM01"] if "injection" in category or "prompt" in category else [],
                    cwe_ids=["CWE-1427"] if "injection" in category or "jailbreak" in category else [],
                    owasp_mcp_tags=["MCP04", "MCP07"] if category == "mcp_blocklist" else [],
                    nist_ai_rmf_tags=["MAP-4.1", "MEASURE-2.6"],
                    evidence={
                        "category": category,
                        "package": item.get("package"),
                        "server": item.get("server"),
                        "context": item.get("context"),
                        "confidence": item.get("confidence"),
                        "evidence_source": item.get("evidence_source"),
                        "source_line": item.get("source_line"),
                        "ai_detected": item.get("ai_detected"),
                        "scanner": "skill_audit",
                    },
                    risk_score=_risk_score(severity),
                )
            )
        )
    return unified


def _safe_relative_path(value: object) -> str | None:
    """A repository-relative path that is safe to publish as a SARIF/finding location."""
    if not isinstance(value, str) or not value or value.startswith(("/", "\\", "~", "<")) or ":" in value:
        return None
    parts = Path(value).parts
    return value if parts and ".." not in parts else None


def _without_host_path(text: str, source_file: str) -> str:
    """Scanner prose names the file it read; findings name only its basename."""
    if not source_file or source_file not in text:
        return text
    return text.replace(source_file, Path(source_file).name or "skill file")
