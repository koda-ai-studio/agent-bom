"""Every finding type maps to a concrete issue class; the UI reads the backend's ``finding_class``."""

from __future__ import annotations

import pytest

from agent_bom import finding_scope
from agent_bom.finding import FindingType


@pytest.mark.parametrize("finding_type", [t.value for t in FindingType])
def test_every_finding_type_has_a_class(finding_type: str) -> None:
    assert finding_scope.finding_class_for_row({"finding_type": finding_type, "source": "MCP_SCAN"}) != "unclassified"


@pytest.mark.parametrize("source", ["CLOUD_SECURITY", "CLOUD_CIS"])
def test_explicit_cve_type_is_a_vulnerability_whatever_the_reporting_source(source: str) -> None:
    """A host CVE reported by a cloud security source is still a CVE.

    The posture dimension counted it as a vulnerability (finding type) while the
    overview's CVE tile dropped it (source-derived class), so the two "open CVE"
    totals disagreed on the same rows.
    """
    row = {"finding_type": "CVE", "source": source, "cve_id": "CVE-2024-6387"}
    assert finding_scope.finding_class_for_row(row) == "vulnerability"
    assert finding_scope.finding_class_for_row({"finding_type": "CLOUD_BEST_PRACTICE_FAIL", "source": source}) == "misconfiguration"
    assert finding_scope.finding_class_for_row({"source": source}) == "misconfiguration"
