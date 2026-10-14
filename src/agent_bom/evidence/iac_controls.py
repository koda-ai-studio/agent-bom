"""Scored control tags for the NIST SP 800-53 controls an IaC rule declares.

IaC rules list the controls they check (``NIST-AC-3``, bare ``AC-3``) alongside
CIS benchmark and ATT&CK IDs in one flat list. Only IDs in the bundled 800-53
catalog are emitted, FedRAMP follows from its Moderate baseline, and detective /
unevaluable controls are dropped, as in the CVE tagger. ``CIS-AWS-*`` benchmark
IDs are not CIS Controls v8 safeguards and are left out of ``cis_tags``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from agent_bom.compliance_hub import apply_hub_classification
from agent_bom.evidence.control_modes import finding_taggable_controls
from agent_bom.fedramp import FEDRAMP_MODERATE
from agent_bom.nist_800_53 import NIST_800_53

if TYPE_CHECKING:
    from agent_bom.finding import Finding

__all__ = ["classify_iac_finding", "iac_declared_controls"]


def iac_declared_controls(compliance: Iterable[str]) -> tuple[list[str], list[str]]:
    """Return ``(nist_800_53_tags, fedramp_tags)`` for the catalog controls an IaC rule declares."""
    declared = {control for raw in compliance if (control := str(raw).strip().upper().removeprefix("NIST-")) in NIST_800_53}
    nist = sorted(finding_taggable_controls("nist_800_53_tags", declared))
    fedramp = finding_taggable_controls("fedramp_tags", {f"FedRAMP-{control}" for control in nist if control in FEDRAMP_MODERATE})
    return nist, sorted(fedramp)


def classify_iac_finding(finding: Finding, compliance: Iterable[str]) -> Finding:
    """Tag an IaC finding with its declared catalog controls, then apply hub classification."""
    finding.nist_800_53_tags, finding.fedramp_tags = iac_declared_controls(compliance)
    return apply_hub_classification(finding)
