"""Project IaC, AI inventory and cloud CIS results into a shared SARIF catalog."""

from __future__ import annotations

from typing import Any

from agent_bom.models import AIBOMReport
from agent_bom.output.advisory_text import advisory_help, sanitize_advisory_text
from agent_bom.output.sarif_common import (
    _sanitize_sarif_property,
    _sarif_fingerprint_fields,
    _sarif_location,
    _sarif_severity,
    _SarifCatalog,
    _to_relative_path,
)
from agent_bom.output.sarif_iac import iac_rule, iac_rule_id, iac_shared_compliance
from agent_bom.security import sanitize_url


def _cis_remediation_text(remediation: Any) -> str:
    """Flatten a CIS remediation dict into one sanitized guidance line."""
    if not isinstance(remediation, dict):
        return ""
    parts = [sanitize_advisory_text("recommendation", remediation.get(key)) for key in ("fix_cli", "fix_console")]
    return " ".join(part for part in parts if part)


# Cloud providers whose CIS benchmark failures are emitted by the dedicated CIS
# loop (_add_cis_benchmark_results) with per-check rule IDs + structured remediation. The
# unified non-CVE loop skips these so each failed check yields exactly one SARIF
# result (no duplicate ruleId+location) in the GitHub Security tab. databricks
# CIS and snowflake governance findings have no dedicated loop, so they keep
# flowing through the unified path.
_DEDICATED_CIS_BENCHMARKS: tuple[tuple[str, str], ...] = (
    ("aws", "cis_benchmark_data"),
    ("azure", "azure_cis_benchmark_data"),
    ("gcp", "gcp_cis_benchmark_data"),
    ("snowflake", "snowflake_cis_benchmark_data"),
)
_DEDICATED_CIS_PROVIDERS = frozenset(provider for provider, _ in _DEDICATED_CIS_BENCHMARKS)


def _add_iac_results(catalog: _SarifCatalog, report: AIBOMReport) -> None:
    """IaC misconfiguration findings (Dockerfile, K8s, Terraform, CloudFormation)."""
    iac_data = getattr(report, "iac_findings_data", None)
    if not iac_data:
        return
    findings = iac_data.get("findings", [])
    shared_compliance = iac_shared_compliance(findings)
    for iac_finding in findings:
        sev = iac_finding.get("severity", "medium").lower()
        rule_id = iac_rule_id(iac_finding)
        level, security_severity = _sarif_severity(sev)
        file_path = _to_relative_path(iac_finding.get("file_path", "unknown") or "unknown")
        line_num = iac_finding.get("line_number") or 1
        if catalog.claim_rule(rule_id):
            catalog.rules.append(iac_rule(iac_finding, rule_id, level, security_severity, shared_compliance[rule_id]))

        fp_input = f"{rule_id}:{file_path}:{line_num}"
        catalog.results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "kind": "fail",
                "message": {
                    "text": sanitize_advisory_text(
                        "description",
                        iac_finding.get("message"),
                        fallback=sanitize_advisory_text("title", iac_finding.get("title", "IaC misconfiguration")),
                    )
                },
                **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=file_path, start_line=line_num),
                "locations": [_sarif_location(file_path, line_num)],
                "properties": {"compliance": list(iac_finding.get("compliance") or [])},
            }
        )


def _ai_inventory_rule(comp: dict[str, Any], rule_id: str, name: str, level: str, security_severity: str) -> dict[str, Any]:
    sev = comp.get("severity", "info")
    comp_type = comp.get("type", "unknown")
    description = sanitize_advisory_text(
        "description",
        comp.get("description", ""),
        fallback=f"AI component finding: {name}",
    )
    ai_rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": sanitize_advisory_text("title", f"{sev.upper()}: {comp_type.replace('_', ' ')} - {name}")},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": level},
        "properties": {"security-severity": security_severity},
    }
    help_body = advisory_help(
        description,
        remediation=sanitize_advisory_text("recommendation", comp.get("recommendation")),
    )
    if help_body:
        ai_rule["help"] = help_body
    return ai_rule


def _add_ai_inventory_results(catalog: _SarifCatalog, report: AIBOMReport) -> None:
    """AI inventory findings (shadow AI, deprecated models, API keys, invisible Unicode)."""
    ai_inv = getattr(report, "ai_inventory_data", None)
    if not ai_inv:
        return
    for comp in ai_inv.get("components", []):
        sev = comp.get("severity", "info")
        if sev not in ("critical", "high", "medium"):
            continue  # only actionable findings in SARIF
        comp_type = comp.get("type", "unknown")
        # Redact credential fragments — never embed key material in SARIF
        raw_name = comp.get("name", "")
        name = "[REDACTED]" if comp_type == "api_key" else raw_name
        rule_id = f"ai-inventory/{comp_type}/{name}"
        level, security_severity = _sarif_severity(sev)
        if catalog.claim_rule(rule_id):
            catalog.rules.append(_ai_inventory_rule(comp, rule_id, name, level, security_severity))

        file_path = _to_relative_path(comp.get("file", "unknown") or "unknown")
        line_num = int(comp.get("line", 1) or 1)
        fp_input = f"{rule_id}:{file_path}:{line_num}"
        desc = sanitize_advisory_text("description", comp.get("description", ""), fallback=f"{comp_type.replace('_', ' ')}: {name}")
        catalog.results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "kind": "fail",
                "message": {"text": desc},
                **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=file_path, start_line=line_num),
                "locations": [_sarif_location(file_path, comp.get("line", 1))],
            }
        )


def _cis_rule(check: dict[str, Any], cloud_key: str, rule_id: str, level: str, security_severity: str) -> dict[str, Any]:
    cis_severity = str(check.get("severity") or "unknown").lower()
    check_id = check.get("check_id") or "unknown"
    remediation = check.get("remediation") or {}
    title = check.get("title") or rule_id
    help_uri = sanitize_url(str(remediation.get("docs") or "")) or ""
    recommendation = sanitize_advisory_text(
        "recommendation",
        check.get("recommendation"),
        fallback=sanitize_advisory_text("title", title, fallback=rule_id),
    )
    cis_rule: dict = {
        "id": rule_id,
        "shortDescription": {
            "text": sanitize_advisory_text(
                "title",
                f"{cis_severity.upper()}: CIS {cloud_key.upper()} {check_id} - {title}",
                fallback=rule_id,
            )
        },
        "fullDescription": {"text": recommendation},
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": security_severity,
            "tags": ["cis", cloud_key, "compliance"],
            "cis_section": check.get("cis_section") or "",
        },
    }
    if help_uri:
        cis_rule["helpUri"] = help_uri
    help_body = advisory_help(
        recommendation,
        remediation=_cis_remediation_text(remediation),
        reference_uri=help_uri,
    )
    if help_body:
        cis_rule["help"] = help_body
    return cis_rule


def _cis_result_properties(check: dict[str, Any]) -> dict[str, Any]:
    remediation = check.get("remediation") or {}
    result_props: dict = {
        "remediation": remediation,
        "cis_section": check.get("cis_section") or "",
        "evidence": _sanitize_sarif_property(check.get("evidence") or ""),
        "resource_ids": _sanitize_sarif_property(check.get("resource_ids") or []),
    }
    # Surface the remediation knobs flat for consumers that
    # can't (or don't want to) read nested dicts.
    if remediation:
        result_props["fix_cli"] = remediation.get("fix_cli")
        result_props["fix_console"] = remediation.get("fix_console") or ""
        result_props["effort"] = remediation.get("effort") or "manual"
        result_props["priority"] = remediation.get("priority") or 3
        result_props["guardrails"] = remediation.get("guardrails") or []
        result_props["requires_human_review"] = bool(remediation.get("requires_human_review"))
    return result_props


def _cis_result(check: dict[str, Any], cloud_key: str, rule_id: str, level: str) -> dict[str, Any]:
    check_id = check.get("check_id") or "unknown"
    title = check.get("title") or rule_id
    # Synthetic fingerprint so repeat runs produce stable IDs.
    fp_input = f"{rule_id}:{','.join(check.get('resource_ids') or [])}"
    # CIS findings are cloud-control-level, not file-level. Point
    # at a conventional manifest so GitHub renders the result;
    # the rich context lives in ``properties``.
    artifact_uri = f"cis-{cloud_key}-benchmark"
    return {
        "ruleId": rule_id,
        "level": level,
        "kind": "fail",
        "message": {
            "text": sanitize_advisory_text(
                "title",
                f"CIS {cloud_key.upper()} {check_id} failed: {title}",
                fallback=rule_id,
            )
        },
        **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=artifact_uri, start_line=1),
        "locations": [_sarif_location(artifact_uri, 1)],
        "properties": _cis_result_properties(check),
    }


def _add_cis_benchmark_results(catalog: _SarifCatalog, report: AIBOMReport) -> None:
    """CIS benchmark findings (AWS / Azure / GCP / Snowflake).

    Each failed check emits a SARIF result with the structured remediation dict
    (issue #665) in ``properties.remediation`` so GitHub Code Scanning and
    downstream SARIF consumers can surface fix guidance per finding.
    """
    from agent_bom.cloud.cis_remediation import fail_closed_cis_bundle

    for cloud_key, data_attr in _DEDICATED_CIS_BENCHMARKS:
        bundle = getattr(report, data_attr, None)
        if not bundle:
            continue
        bundle = fail_closed_cis_bundle(bundle, cloud=cloud_key)
        for check in bundle.get("checks", []):
            if check.get("status") != "fail":
                continue
            # Matches `cis_check_to_finding`: a control that reports no severity
            # is unrated, not medium. Defaulting to a rated band here published
            # the check to GitHub as Medium while every summary built from the
            # unified stream called the same check unrated.
            cis_severity = str(check.get("severity") or "unknown").lower()
            rule_id = f"cis/{cloud_key}/{check.get('check_id') or 'unknown'}"
            level, security_severity = _sarif_severity(cis_severity)
            if catalog.claim_rule(rule_id):
                catalog.rules.append(_cis_rule(check, cloud_key, rule_id, level, security_severity))
            catalog.results.append(_cis_result(check, cloud_key, rule_id, level))
