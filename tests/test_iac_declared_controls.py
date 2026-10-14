"""IaC rules declare the NIST SP 800-53 controls they check; those land in the scored tag fields.

An IaC finding carried ``NIST-AC-3`` only in the flat ``compliance_tags``, so
``/v1/compliance/nist-800-53`` and ``/fedramp`` never counted it while its
``applicable_frameworks`` claimed both. ``CIS-AWS-*`` IDs name CIS AWS
Foundations Benchmark checks, not CIS Controls v8 safeguards, so they never
enter ``cis_tags``.
"""

from __future__ import annotations

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, control_key_for_tag
from agent_bom.evidence.iac_controls import iac_declared_controls
from agent_bom.finding import iac_finding_to_finding


def _iac(compliance: list[str]) -> dict:
    return {
        "rule_id": "TF-SEC-002",
        "file_path": "main.tf",
        "line_number": 3,
        "severity": "high",
        "title": "S3 public",
        "compliance": compliance,
    }


def test_declared_nist_controls_reach_nist_and_fedramp_fields() -> None:
    finding = iac_finding_to_finding(_iac(["CIS-AWS-2.1.2", "NIST-AC-3", "T1190", "2.1.2", "AC-3"]))
    assert finding.nist_800_53_tags == ["AC-3"]
    assert finding.fedramp_tags == ["FedRAMP-AC-3"]
    assert finding.cis_tags == [], "a CIS AWS Foundations check is not a CIS Controls v8 safeguard"
    assert {"nist-800-53", "fedramp"} <= set(finding.applicable_frameworks)


def test_only_catalog_controls_are_emitted() -> None:
    # CP-9 is not in the bundled 800-53 catalog; emitting it would tag a control no line can score.
    assert iac_declared_controls(["NIST-CP-9", "CP-9"]) == {}
    assert iac_declared_controls(["nist-au-2"]) == {"nist_800_53_tags": ["AU-2"], "fedramp_tags": ["FedRAMP-AU-2"]}
    assert iac_declared_controls([]) == {}


def test_every_emitted_tag_resolves_in_its_scoring_catalog() -> None:
    finding = iac_finding_to_finding(_iac(["NIST-AC-3", "NIST-AU-2", "NIST-CP-9"]))
    for metadata in TAG_MAPPED_FRAMEWORKS:
        for tag in getattr(finding, metadata.tag_field):
            assert control_key_for_tag(str(tag), dict(metadata.catalog)), (metadata.tag_field, tag)


def test_detective_and_unevaluable_controls_are_never_tagged() -> None:
    """IaC rules list RA-5 / CM-8; tagging a finding onto them would fail the scan-is-the-evidence controls."""
    assert iac_declared_controls(["NIST-RA-5", "NIST-CM-8", "NIST-RA-7"]) == {}
    assert iac_declared_controls(["NIST-RA-5", "NIST-AC-6"]) == {"nist_800_53_tags": ["AC-6"], "fedramp_tags": ["FedRAMP-AC-6"]}
