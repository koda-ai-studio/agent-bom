"""SARIF rule metadata for IaC misconfiguration findings.

A SARIF rule is shared by every result that references it, so it carries only
instance-independent text and the compliance IDs every instance shares. The
resource-specific message and each instance's own controls (provider-scoped
CIS IDs, for example) stay on the result.
"""

from __future__ import annotations

from typing import Any

from agent_bom.output.advisory_text import advisory_help, sanitize_advisory_text
from agent_bom.security import sanitize_sensitive_payload

_SUPPRESSION_PROPERTIES = ("source", "origin", "owner", "expires", "approved_by", "exception_id", "state")


def iac_rule_id(iac_finding: dict[str, Any]) -> str:
    return f"iac/{iac_finding.get('rule_id', 'unknown')}"


def iac_rule(iac_finding: dict[str, Any], rule_id: str, level: str, security_severity: str, compliance: list[str]) -> dict[str, Any]:
    description = sanitize_advisory_text("title", iac_finding.get("title", rule_id), fallback=rule_id)
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": description},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": security_severity,
            "category": iac_finding.get("category", "iac"),
            "compliance": compliance,
        },
    }
    help_body = advisory_help(
        description if description.endswith((".", "!", "?")) else f"{description}.",
        remediation=sanitize_advisory_text("recommendation", iac_finding.get("remediation")),
    )
    if help_body:
        rule["help"] = help_body
    return rule


def iac_shared_compliance(findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Per rule, the compliance IDs every instance carries (order of first sight)."""
    shared: dict[str, list[str]] = {}
    for iac_finding in findings:
        rule_id = iac_rule_id(iac_finding)
        ids = list(iac_finding.get("compliance") or [])
        shared[rule_id] = [cid for cid in shared[rule_id] if cid in ids] if rule_id in shared else ids
    return shared


def iac_suppressions(iac_finding: dict[str, Any]) -> list[dict[str, Any]]:
    """SARIF 2.1.0 ``suppressions[]`` for an accepted IaC exception (``inSource`` for inline markers)."""
    record = iac_finding.get("suppression")
    if not isinstance(record, dict):
        return []
    entry: dict[str, Any] = {"kind": "inSource" if record.get("source") == "inline" else "external", "status": "accepted"}
    justification = sanitize_sensitive_payload(str(record.get("reason") or ""), key="justification", max_str_len=1000)
    if isinstance(justification, str) and justification:
        entry["justification"] = justification
    properties = {
        key: sanitize_sensitive_payload(str(record[key]), key=key, max_str_len=200) for key in _SUPPRESSION_PROPERTIES if record.get(key)
    }
    if properties:
        entry["properties"] = properties
    return [entry]
