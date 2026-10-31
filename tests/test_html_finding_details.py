"""Compact HTML findings preserve evidence and distinguish missing values from zero."""

import re

import pytest

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.html.sections_findings import _vuln_table


def _finding(**values):
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="requests", asset_type="package"),
        severity="medium",
        title="CVE-2023-32681",
        description="Recorded advisory description.",
        cve_id="CVE-2023-32681",
        evidence={"package_name": "requests", "package_version": "2.25.0", **values.pop("evidence", {})},
        **values,
    )


def test_findings_have_four_overview_columns_and_collapsed_evidence():
    finding = _finding(affected_agents=["project:example"], exposed_credentials=["API_KEY"], fixed_version="2.31.0")
    page = _vuln_table(AIBOMReport(), [], findings=[finding])
    assert len(re.findall(r"<th data-col=", page)) == 4
    assert '<details class="finding-evidence">' in page
    assert "<summary>View evidence</summary>" in page
    for value in ("CVE-2023-32681", "requests", "2.25.0", "2.31.0", "project:example", "API_KEY", finding.description):
        assert value in page


@pytest.mark.parametrize(
    "status,label", [(None, "Not checked"), ("unknown", "Unavailable"), ("not_listed", "Not listed in recorded catalog")]
)
def test_missing_fields_have_explicit_evidence_states(status, label):
    page = _vuln_table(AIBOMReport(), [], findings=[_finding(evidence={"kev_status": status})])
    assert label in page
    assert "No score recorded" in page
    assert "No reachability verdict" in page
    assert "None recorded" in page
    assert "No fix recorded" in page


def test_zero_scores_are_values_not_missing_evidence():
    page = _vuln_table(AIBOMReport(), [], findings=[_finding(cvss_score=0.0, epss_score=0.0)])
    assert "0.0%" in page
    assert ">0.0</strong>" in page
    assert "No score recorded" not in page


def test_recorded_staleness_is_visible_beside_findings():
    report = AIBOMReport()
    report.vuln_data_freshness = {"stale": True, "age_days": 73}
    page = _vuln_table(report, [], findings=[_finding()])
    assert "Recorded vulnerability data is stale" in page
    assert "73 days" in page


def test_expanded_evidence_preserves_long_text_and_escapes_untrusted_values():
    finding = _finding(affected_agents=['<script>alert("context")</script>'])
    finding.description = "Long advisory context. " * 100 + '<img src=x onerror="alert(1)">'
    page = _vuln_table(AIBOMReport(), [], findings=[finding])
    assert page.count("Long advisory context.") == 100
    assert "&lt;img" in page
    assert "&lt;script&gt;" in page
    assert "<img" not in page
    assert "<script>" not in page
