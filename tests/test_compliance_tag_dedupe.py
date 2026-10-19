"""A control mapped to a named framework is one control, not a framework copy plus a legacy ``generic`` copy."""

from __future__ import annotations

from agent_bom.compliance_utils import framework_qualified_finding_tags
from agent_bom.finding_runtime_evidence import compliance_tags_from_finding_row


def test_row_flattening_drops_generic_copies_of_framework_controls():
    row = {
        "compliance_tags": ["CIS-02.3", "A.5.19", "LEGACY-ONLY-1"],
        "cis_tags": ["CIS-02.3"],
        "iso_27001_tags": ["A.5.19"],
        "controls": [{"framework": "cis", "control": "CIS-02.3"}],
    }
    assert compliance_tags_from_finding_row(row) == ["cis:CIS-02.3", "generic:LEGACY-ONLY-1", "iso_27001:A.5.19"]


def test_row_flattening_keeps_a_generic_control_with_no_framework_mapping():
    assert compliance_tags_from_finding_row({"compliance_tags": ["CUSTOM-7"]}) == ["generic:CUSTOM-7"]


def test_unified_finding_tags_drop_generic_copies():
    class _Control:
        def __init__(self, framework: str, control: str) -> None:
            self.framework, self.control = framework, control

    class _Finding:
        compliance_tags = ["CIS-02.3", "ONLY-LEGACY"]
        evidence = {"vulnerability_compliance_tags": {"fedramp": ["FedRAMP-SI-2"]}}

        def normalized_controls(self):
            return [_Control("cis", "CIS-02.3"), _Control("generic", "FedRAMP-SI-2")]

    assert framework_qualified_finding_tags(_Finding()) == ["cis:CIS-02.3", "fedramp:FedRAMP-SI-2", "generic:ONLY-LEGACY"]
