"""A probability below 1 never reads as "100.0%", and a positive one never as "0.0%"."""

from __future__ import annotations

import pytest

from agent_bom.output.probability_format import probability_percent


@pytest.mark.parametrize(
    ("value", "text"),
    [(0.99979, "99.98%"), (0.9996, "99.96%"), (0.4567, "45.7%"), (1.0, "100.0%"), (0.0, "0.0%"), (0.0002, "0.02%")],
)
def test_probability_percent(value: float, text: str) -> None:
    assert probability_percent(value) == text


def test_html_finding_row_shows_epss_below_certainty() -> None:
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType
    from agent_bom.models import AIBOMReport
    from agent_bom.output.html.sections_findings import _vuln_table

    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="log4j-core", asset_type="package"),
        severity="critical",
        title="CVE-2021-44228",
        cve_id="CVE-2021-44228",
        epss_score=0.99979,
        evidence={"package_name": "log4j-core", "package_version": "2.14.1"},
    )
    page = _vuln_table(AIBOMReport(), [], findings=[finding])
    assert "99.98%" in page
    assert "100.0%" not in page
