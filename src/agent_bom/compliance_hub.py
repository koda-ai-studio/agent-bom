"""Compliance Hub — context-aware framework selection (#1044 PR A).

The hub answers a single question that every ingestion path needs to make
the same way: *given a finding, which compliance frameworks apply?*

Without this, every adapter (SARIF, CycloneDX, native scanner, external
imports) re-implements the mapping ad hoc — leading to the same finding
landing under different framework sets depending on which entry point
loaded it. The hub centralises the selection so the answer is one function
call regardless of source.

The framework slug vocabulary and the source/asset/finding-type selection
table now live in :mod:`agent_bom.framework_mapping` — the unified mapping
layer that is the single source of truth for "which framework controls does
this signal evidence". The hub re-exports the selection API for backward
compatibility and adds :func:`apply_hub_classification`, which projects that
selection onto a ``Finding``'s ``applicable_frameworks``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, normalize_framework_slug

# The framework vocabulary + selection engine were consolidated into
# ``framework_mapping``. Re-exported here so existing callers importing these
# names from ``compliance_hub`` keep working unchanged.
from agent_bom.framework_mapping import (
    ALL_FRAMEWORKS,
    FRAMEWORK_ATLAS,
    FRAMEWORK_ATTACK,
    FRAMEWORK_CIS,
    FRAMEWORK_CMMC,
    FRAMEWORK_EU_AI_ACT,
    FRAMEWORK_FEDRAMP,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_NIST_800_53,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_OWASP_MCP,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    controls_for_finding_shape,
    is_framework_relevant,
    select_frameworks,
)

if TYPE_CHECKING:
    from agent_bom.finding import Finding

__all__ = [
    "ALL_FRAMEWORKS",
    "FRAMEWORK_ATLAS",
    "FRAMEWORK_ATTACK",
    "FRAMEWORK_CIS",
    "FRAMEWORK_CMMC",
    "FRAMEWORK_EU_AI_ACT",
    "FRAMEWORK_FEDRAMP",
    "FRAMEWORK_ISO_27001",
    "FRAMEWORK_NIST_800_53",
    "FRAMEWORK_NIST_AI_RMF",
    "FRAMEWORK_NIST_CSF",
    "FRAMEWORK_OWASP_AGENTIC",
    "FRAMEWORK_OWASP_LLM",
    "FRAMEWORK_OWASP_MCP",
    "FRAMEWORK_PCI_DSS",
    "FRAMEWORK_SOC2",
    "select_frameworks",
    "is_framework_relevant",
    "apply_hub_classification",
]


def _tag_evidenced_frameworks(finding: "Finding") -> list[str]:
    """Framework slugs on which ``finding`` carries at least one control tag."""
    return [metadata.slug for metadata in TAG_MAPPED_FRAMEWORKS if getattr(finding, metadata.tag_field, None)]


def apply_hub_classification(finding: "Finding", *, include_gov: bool = False) -> "Finding":
    """Populate a finding's control tags and its ``applicable_frameworks``.

    Applicability is the union of any existing entries, the hub selection
    table for the finding's source/asset/finding type, and every framework on
    which the finding carries a control tag. Hub posture counts by
    ``applicable_frameworks`` and ``/v1/compliance`` counts by control tags, so
    a tagged framework missing from applicability would count the finding on
    one surface and not the other.

    Idempotent and additive. Returns the same finding for fluent chaining.
    """
    location = finding.asset.location or (finding.evidence.get("file") if isinstance(finding.evidence, dict) else None)
    rule_id = finding.evidence.get("rule_id") if isinstance(finding.evidence, dict) else None
    shape_tags = controls_for_finding_shape(
        finding.finding_type,
        source=finding.source,
        cwe_ids=finding.cwe_ids,
        asset_type=finding.asset.asset_type,
        location=str(location) if location else None,
        rule_id=str(rule_id) if rule_id else None,
    )
    for tag_field, controls in shape_tags.items():
        existing = list(getattr(finding, tag_field))
        setattr(finding, tag_field, existing + [control for control in controls if control not in existing])

    selected = [normalize_framework_slug(str(slug)) for slug in finding.applicable_frameworks]
    selected += select_frameworks(
        finding.source,
        asset_type=finding.asset.asset_type,
        finding_type=finding.finding_type,
        include_gov=include_gov,
    )
    selected += _tag_evidenced_frameworks(finding)
    seen = set(selected)
    # Canonical order so consumers can hash the list reliably.
    finding.applicable_frameworks = [slug for slug in ALL_FRAMEWORKS if slug in seen] + sorted(seen - set(ALL_FRAMEWORKS))
    return finding
