"""Rehydrate serialized graph-derived findings (toxic combinations, CIEM).

Graph evaluators serialize their findings onto report side blocks; the report
turns them back into :class:`~agent_bom.finding.Finding` objects here, without
importing the graph layer that produced them.
"""

from __future__ import annotations

from agent_bom.finding import LEGACY_CONTROL_FIELDS, Asset, Finding, FindingSource, FindingType


def findings_from_dicts(data: list[dict]) -> list[Finding]:
    """Rehydrate stored graph-derived finding dicts into Findings for the unified stream."""
    findings: list[Finding] = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        finding = finding_from_dict(item)
        if finding is not None:
            findings.append(finding)
    return findings


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


# Report-only values written before browser-extension rows used the enums.
_LEGACY_VALUES = {"BROWSER_EXTENSION_RISK": "BROWSER_EXT", "BROWSER_EXTENSION_SCAN": "BROWSER_EXT"}


def _legacy(value: object) -> object:
    return _LEGACY_VALUES.get(value, value) if isinstance(value, str) else value


def _optional_float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _restore_vulnerability_fields(finding: Finding, item: dict) -> None:
    """Restore the advisory facts a CVE row carries; dropping them read as "no fix, no EPSS"."""
    finding.cvss_score = _optional_float(item.get("cvss_score"))
    finding.epss_score = _optional_float(item.get("epss_score"))
    finding.is_kev = bool(item.get("is_kev"))
    finding.fixed_version = _optional_str(item.get("fixed_version"))
    finding.reachability = _optional_str(item.get("reachability"))
    reachable = item.get("graph_reachable")
    finding.graph_reachable = reachable if isinstance(reachable, bool) else None
    cwes = item.get("cwe_ids")
    if isinstance(cwes, (list, tuple)):
        finding.cwe_ids = [str(cwe) for cwe in cwes if cwe]


def finding_from_dict(item: dict) -> Finding | None:
    """Rehydrate a Finding dict, preserving graph investigation FKs when present."""
    asset_data = item.get("asset") or {}
    asset = Asset(
        name=str(asset_data.get("name", "")),
        asset_type=str(asset_data.get("asset_type", "cloud_resource")),
        identifier=asset_data.get("identifier"),
        location=asset_data.get("location"),
        provider=asset_data.get("provider") or item.get("provider"),
        account_ref=asset_data.get("account_ref") or item.get("account_ref"),
        region=asset_data.get("region") or item.get("region"),
        environment=asset_data.get("environment") or item.get("environment"),
        _recorded_canonical_id=str(asset_data.get("canonical_id") or asset_data.get("stable_id") or ""),
    )
    try:
        finding_type = FindingType(_legacy(item.get("finding_type", "COMBINATION")))
    except ValueError:
        finding_type = FindingType.COMBINATION
    try:
        source = FindingSource(_legacy(item.get("source", "GRAPH_ANALYSIS")))
    except ValueError:
        source = FindingSource.GRAPH_ANALYSIS
    finding = Finding(
        finding_type=finding_type,
        source=source,
        asset=asset,
        severity=str(item.get("severity", "high")),
        severity_source=_optional_str(item.get("severity_source")),
        title=str(item.get("title", "")),
        description=str(item.get("description", "")),
        remediation_guidance=item.get("remediation_guidance"),
        evidence=item.get("evidence", {}) or {},
        risk_score=_optional_float(item.get("risk_score")),
        is_actionable=item.get("is_actionable"),
        impact_category=item.get("impact_category"),
        id=str(item.get("id", "")),
        cve_id=_optional_str(item.get("cve_id")),
        node_id=_optional_str(item.get("node_id")),
        finding_node_id=_optional_str(item.get("finding_node_id")),
        entity_type=_optional_str(item.get("entity_type")),
    )
    # ``compliance_tags`` serializes as the union of every framework's tags, so
    # only the per-framework arrays are restored.
    for tag_field, _framework in LEGACY_CONTROL_FIELDS:
        if tag_field == "compliance_tags":
            continue
        values = item.get(tag_field)
        if isinstance(values, (list, tuple)):
            setattr(finding, tag_field, [str(value) for value in values if value])
    _restore_vulnerability_fields(finding, item)
    applicable = item.get("applicable_frameworks")
    if isinstance(applicable, (list, tuple)):
        finding.applicable_frameworks = [str(slug) for slug in applicable if slug]
    return finding
