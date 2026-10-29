"""Convert persisted unified findings into narrative evidence without rescanning."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import SimpleNamespace

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS


def _row_cwe_ids(row: Mapping[str, object]) -> list[str]:
    raw = row.get("cwe_ids")
    return [str(cwe) for cwe in raw if str(cwe).strip()] if isinstance(raw, (list, tuple)) else []


def _framework_tag_aliases() -> dict[str, str]:
    tag_aliases: dict[str, str] = {}
    for metadata in TAG_MAPPED_FRAMEWORKS:
        for alias in (
            metadata.slug,
            metadata.slug.replace("-", "_"),
            metadata.output_key,
            metadata.summary_prefix,
            metadata.tag_field.removesuffix("_tags"),
        ):
            tag_aliases[alias.lower().replace("-", "_")] = metadata.tag_field
    return tag_aliases


def _row_control_tags(row: Mapping[str, object], tag_aliases: dict[str, str]) -> dict[str, list[str]]:
    tag_values: dict[str, list[str]] = {metadata.tag_field: [] for metadata in TAG_MAPPED_FRAMEWORKS}
    for metadata in TAG_MAPPED_FRAMEWORKS:
        raw_tags = row.get(metadata.tag_field)
        if isinstance(raw_tags, (list, tuple, set)):
            tag_values[metadata.tag_field].extend(str(tag) for tag in raw_tags if str(tag).strip())

    controls = row.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if not isinstance(control, Mapping):
                continue
            framework_name = str(control.get("framework") or "").strip().lower().replace("-", "_")
            tag_field = tag_aliases.get(framework_name)
            control_id = str(control.get("control") or control.get("id") or "").strip()
            if tag_field and control_id:
                tag_values[tag_field].append(control_id)

    flattened = row.get("framework_tags")
    if isinstance(flattened, list):
        for item in flattened:
            prefix, separator, control_id = str(item).partition(":")
            tag_field = tag_aliases.get(prefix.strip().lower().replace("-", "_"))
            if separator and tag_field and control_id.strip():
                tag_values[tag_field].append(control_id.strip())

    tag_values = {tag_field: list(dict.fromkeys(values)) for tag_field, values in tag_values.items()}
    return tag_values


def _finding_blast_radius(row: Mapping[str, object], tag_values: dict[str, list[str]]) -> SimpleNamespace:
    raw_asset = row.get("asset")
    asset: Mapping[str, object] = raw_asset if isinstance(raw_asset, Mapping) else {}
    package_value = str(row.get("package") or row.get("package_name") or asset.get("name") or "Unavailable")
    if "@" in package_value:
        package_name, package_version = package_value.rsplit("@", 1)
    else:
        package_name = package_value
        package_version = str(row.get("package_version") or "")
    severity = str(row.get("effective_severity") or row.get("severity") or "unknown").lower()
    vulnerability_id = str(row.get("cve_id") or row.get("vulnerability_id") or row.get("id") or "Unavailable")
    raw_risk_score = row.get("risk_score") or row.get("effective_reach_score") or 0
    try:
        risk_score = float(raw_risk_score) if isinstance(raw_risk_score, int | float | str) else 0.0
    except ValueError:
        risk_score = 0.0
    raw_agents = row.get("affected_agents")
    affected_agents = raw_agents if isinstance(raw_agents, (list, tuple, set)) else []
    if not affected_agents and asset.get("asset_type") == "agent" and asset.get("name"):
        # The finding is about this agent (e.g. a toxic combination on it).
        affected_agents = [asset["name"]]
    raw_servers = row.get("affected_servers")
    affected_servers = raw_servers if isinstance(raw_servers, (list, tuple, set)) else []
    raw_credentials = row.get("exposed_credentials")
    exposed_credentials = raw_credentials if isinstance(raw_credentials, (list, tuple, set)) else []
    return SimpleNamespace(
        vulnerability=SimpleNamespace(
            id=vulnerability_id,
            severity=SimpleNamespace(value=severity),
            fixed_version=row.get("fixed_version"),
            is_kev=bool(row.get("is_kev")),
            cwe_ids=_row_cwe_ids(row),
        ),
        package=SimpleNamespace(name=package_name, version=package_version),
        risk_score=risk_score,
        affected_agents=[SimpleNamespace(name=str(name)) for name in affected_agents],
        affected_servers=[SimpleNamespace(name=str(name)) for name in affected_servers],
        exposed_credentials=[str(name) for name in exposed_credentials],
        finding_type=str(row.get("finding_type") or "CVE"),
        title=str(row["title"]) if row.get("title") else None,
        owner=row.get("owner"),
        sla_due_at=row.get("sla_due_at"),
        **tag_values,
    )


def blast_radii_from_finding_rows(findings: Iterable[Mapping[str, object]]) -> list[SimpleNamespace]:
    """Project rows while preserving control tags, finding type, owner and SLA."""
    tag_aliases = _framework_tag_aliases()
    return [_finding_blast_radius(row, _row_control_tags(row, tag_aliases)) for row in findings]
