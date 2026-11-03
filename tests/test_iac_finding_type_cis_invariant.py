"""Only IaC rules that cite a CIS benchmark control are typed ``CIS_FAIL``.

``GHA-002`` (unpinned action) cites no CIS control, so calling it a CIS failure
put it in CIS framework rollups it never evidenced. Rules that do cite one
(``DOCKER-006`` -> CIS Docker Benchmark 4.6, HEALTHCHECK) stay ``CIS_FAIL``.
"""

from __future__ import annotations

from dataclasses import asdict

import pytest

from agent_bom.finding import FindingType, iac_finding_to_finding
from agent_bom.finding_scope import finding_class_for_row, security_domain_for
from agent_bom.iac import scan_iac_directory
from agent_bom.iac.models import cites_cis_control
from agent_bom.models import AIBOMReport
from agent_bom.output.sarif import to_sarif


def _row(rule_id: str, compliance: list[str]) -> dict:
    return {"rule_id": rule_id, "severity": "medium", "title": rule_id, "file_path": "x", "line_number": 1, "compliance": compliance}


def test_non_cis_rule_is_an_iac_misconfiguration_not_a_cis_failure() -> None:
    finding = iac_finding_to_finding(_row("GHA-002", []))
    assert finding.finding_type is FindingType.IAC_MISCONFIGURATION
    assert finding.cis_tags == []
    assert finding.evidence["iac"] is True
    assert security_domain_for(finding.source, finding.finding_type, finding.evidence) == "aspm"
    assert finding_class_for_row({"finding_type": finding.finding_type.value, "source": finding.source.value}) == "misconfiguration"


def test_nist_only_rule_is_not_a_cis_failure() -> None:
    finding = iac_finding_to_finding(_row("K8S-099", ["NIST-AC-6"]))
    assert finding.finding_type is FindingType.IAC_MISCONFIGURATION
    assert finding.nist_800_53_tags == ["AC-6"]


@pytest.mark.parametrize("compliance", [["CIS-Docker-4.6", "NIST-SI-4"], ["CIS-AWS-2.1.1"], ["CIS-K8S-5.2.1"], ["CIS-5.1"]])
def test_cis_cited_rule_stays_cis_fail(compliance: list[str]) -> None:
    assert iac_finding_to_finding(_row("DOCKER-006", compliance)).finding_type is FindingType.CIS_FAIL


@pytest.mark.parametrize(
    "tag, expected",
    [
        ("CIS-Docker-4.6", True),
        ("cis-aws-1.4", True),
        ("CIS-5.1", True),
        ("CIS", False),
        ("CISA-KEV", False),
        ("NIST-CM-7", False),
        ("", False),
    ],
)
def test_cites_cis_control(tag: str, expected: bool) -> None:
    assert cites_cis_control([tag]) is expected


def test_every_shipped_iac_rule_type_matches_its_cis_citation(tmp_path) -> None:
    """Invariant over real scanner output: CIS_FAIL <=> the rule cites a CIS control id."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nRUN pip install flask\n", encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    raw = [asdict(f) for f in scan_iac_directory(tmp_path)]
    assert {"DOCKER-006", "GHA-002"} <= {r["rule_id"] for r in raw}
    for row in raw:
        finding = iac_finding_to_finding(row)
        expected = FindingType.CIS_FAIL if cites_cis_control(row.get("compliance") or []) else FindingType.IAC_MISCONFIGURATION
        assert finding.finding_type is expected, row["rule_id"]


def test_iac_misconfiguration_is_emitted_once_in_sarif() -> None:
    row = _row("GHA-002", [])
    report = AIBOMReport(iac_findings_data={"findings": [row]})
    results = to_sarif(report)["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["iac/GHA-002"]
