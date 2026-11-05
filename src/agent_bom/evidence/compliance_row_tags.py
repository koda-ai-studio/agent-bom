"""Framework control tags flattened from a finding row."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.evidence.compliance_tag_dedupe import drop_generic_duplicates

_FIELD_TO_FRAMEWORK = {
    "owasp_tags": "owasp_llm",
    "atlas_tags": "atlas",
    "nist_ai_rmf_tags": "nist_ai_rmf",
    "owasp_mcp_tags": "owasp_mcp",
    "owasp_agentic_tags": "owasp_agentic",
    "eu_ai_act_tags": "eu_ai_act",
    "nist_csf_tags": "nist_csf",
    "iso_27001_tags": "iso_27001",
    "soc2_tags": "soc2",
    "cis_tags": "cis",
    "cmmc_tags": "cmmc",
    "nist_800_53_tags": "nist_800_53",
    "fedramp_tags": "fedramp",
    "pci_dss_tags": "pci_dss",
    "attack_tags": "attack",
}


def _declared_tags(raw: object) -> list[tuple[str, object]]:
    """``(framework, control)`` pairs from a row's ``compliance_tags``, a mapping or a list."""
    if isinstance(raw, list):
        return [("generic", value) for value in raw]
    if not isinstance(raw, dict):
        return []
    declared: list[tuple[str, object]] = []
    for framework, values in sorted(raw.items()):
        items = [values] if isinstance(values, str) else values if isinstance(values, list) else []
        declared.extend((str(framework), value) for value in items)
    return declared


def compliance_tags_from_finding_row(row: Mapping[str, Any]) -> list[str]:
    """Flatten framework control tags already present on a finding row."""
    tags: list[str] = []
    seen: set[str] = set()

    def add(framework: str, control: object) -> None:
        control_text = str(control or "").strip()
        if not control_text:
            return
        value = control_text if ":" in control_text else f"{framework}:{control_text}"
        if value not in seen:
            seen.add(value)
            tags.append(value)

    for framework, value in _declared_tags(row.get("compliance_tags")):
        add(framework, value)
    for tag_field, framework in _FIELD_TO_FRAMEWORK.items():
        values = row.get(tag_field)
        if isinstance(values, list):
            for value in values:
                add(framework, value)

    controls = row.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict):
                add(str(control.get("framework") or "generic"), control.get("control") or control.get("id"))

    return sorted(drop_generic_duplicates(tags))
