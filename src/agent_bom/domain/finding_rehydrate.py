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


def finding_from_dict(item: dict) -> Finding | None:
    """Rehydrate a Finding dict, preserving graph investigation FKs when present."""
    asset_data = item.get("asset") or {}
    asset = Asset(
        name=str(asset_data.get("name", "")),
        asset_type=str(asset_data.get("asset_type", "cloud_resource")),
        identifier=asset_data.get("identifier"),
        location=asset_data.get("location"),
    )
    try:
        finding_type = FindingType(item.get("finding_type", FindingType.COMBINATION.value))
    except ValueError:
        finding_type = FindingType.COMBINATION
    try:
        source = FindingSource(item.get("source", FindingSource.GRAPH_ANALYSIS.value))
    except ValueError:
        source = FindingSource.GRAPH_ANALYSIS
    finding = Finding(
        finding_type=finding_type,
        source=source,
        asset=asset,
        severity=str(item.get("severity", "high")),
        title=str(item.get("title", "")),
        description=str(item.get("description", "")),
        remediation_guidance=item.get("remediation_guidance"),
        evidence=item.get("evidence", {}) or {},
        risk_score=float(item.get("risk_score", 0.0) or 0.0),
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
    applicable = item.get("applicable_frameworks")
    if isinstance(applicable, (list, tuple)):
        finding.applicable_frameworks = [str(slug) for slug in applicable if slug]
    return finding
