"""Project the canonical current finding queue into package upgrade actions."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, resolve_framework_filter
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.finding_scope import safe_finding_response_payload
from agent_bom.output.json_fmt import remediation_json


class CurrentRemediationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["remediation.current.v1"] = "remediation.current.v1"
    remediation_plan: list[dict[str, Any]]
    source_findings: int
    truncated: bool
    warnings: list[str]
    window: dict[str, Any] | None = None


def remediation_finding_projection(row: dict[str, Any]) -> dict[str, Any]:
    """Default-deny projection of the fields consumed by upgrade actions.

    Avoid projecting full control records, graph context and asset attributes
    for every finding. The retained fields pass through the same safe response
    boundary as the full finding view; no unredacted values leave this module.
    """
    fields = {
        "cve_id",
        "vulnerability_id",
        "suppressed",
        "package_name",
        "package",
        "package_version",
        "ecosystem",
        "references",
        "severity",
        "title",
        "fixed_version",
        "is_kev",
        "risk_score",
        "affected_agents",
        "exposed_credentials",
        "exposed_tools",
        "owasp_tags",
        "atlas_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
    }
    projected = {key: row[key] for key in fields if key in row}
    qualified = [
        f"{metadata.slug}:{control}" for metadata in TAG_MAPPED_FRAMEWORKS for control in _strings(projected.get(metadata.tag_field))[:200]
    ]
    projected["framework_tags"] = (_strings(row.get("framework_tags"))[:200] + qualified)[:200]
    evidence = row.get("evidence")
    if isinstance(evidence, dict):
        projected["evidence"] = {
            key: evidence[key]
            for key in (
                "package_name",
                "package_version",
                "ecosystem",
                "references",
                "fixed_version",
            )
            if key in evidence
        }
    payload = safe_finding_response_payload(projected)
    # Restore only sanitized, catalogued tags already present in this finding.
    # Upgrade actions consume legacy fields; the safe boundary retains the
    # qualified framework_tags representation instead of those raw arrays.
    validated_tags = []
    for tag in _strings(payload.pop("framework_tags", None)):
        framework, separator, control = tag.partition(":")
        metadata = resolve_framework_filter(framework) if separator else None
        if metadata and metadata.tag_field in fields and control in metadata.catalog:
            validated_tags.append(tag)
            tags = payload.setdefault(metadata.tag_field, [])
            if control not in tags:
                tags.append(control)
    if validated_tags:
        payload["framework_tags"] = list(dict.fromkeys(validated_tags))
    # Tier-A redaction drops these lists wholesale. Their entries are reference
    # names (env-var and tool names, as the agent detail and per-scan plan
    # already return), so restore only entries shaped like a name, never a value.
    for key in ("exposed_credentials", "exposed_tools"):
        names = [value for value in _strings(row.get(key))[:200] if _REFERENCE_NAME.fullmatch(value)]
        if names:
            payload[key] = list(dict.fromkeys(names))
    return payload


_REFERENCE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]{0,127}")


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _package_finding(row: dict[str, Any]) -> Finding | None:
    advisory = row.get("cve_id") or row.get("vulnerability_id")
    if not advisory or row.get("suppressed"):
        return None
    evidence = dict(row["evidence"]) if isinstance(row.get("evidence"), dict) else {}
    name = str(row.get("package_name") or row.get("package") or evidence.get("package_name") or "")
    version = str(row.get("package_version") or evidence.get("package_version") or "")
    if "@" in name and name.rsplit("@", 1)[0]:
        name, reported_version = name.rsplit("@", 1)
        version = version or reported_version
    if not name:
        return None
    evidence.update(package_name=name, package_version=version, ecosystem=row.get("ecosystem") or evidence.get("ecosystem", ""))
    evidence["references"] = _strings(row.get("references") or evidence.get("references"))
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name=name, asset_type="package"),
        severity=str(row.get("severity") or "unknown"),
        title=str(row.get("title") or advisory),
        cve_id=str(advisory),
        fixed_version=row.get("fixed_version") or evidence.get("fixed_version"),
        evidence=evidence,
        is_kev=bool(row.get("is_kev")),
        risk_score=float(row.get("risk_score") or 0),
    )
    for field in (
        "affected_agents",
        "exposed_credentials",
        "exposed_tools",
        "owasp_tags",
        "atlas_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
    ):
        setattr(finding, field, _strings(row.get(field)))
    return finding


def current_remediation_response(snapshot: dict[str, Any], window: dict[str, Any] | None = None) -> CurrentRemediationResponse:
    rows = snapshot.get("findings", [])
    findings = [finding for row in rows if isinstance(row, dict) and (finding := _package_finding(row)) is not None]
    return CurrentRemediationResponse(
        remediation_plan=remediation_json(findings),
        source_findings=len(rows),
        truncated=snapshot.get("completeness", {}).get("status") != "complete",
        warnings=_strings(snapshot.get("warnings")),
        window=window,
    )
