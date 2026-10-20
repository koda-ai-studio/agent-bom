"""An unscored vulnerability renders as "not assessed" everywhere, never as risk 0 or a crash."""

from __future__ import annotations

import pytest

from agent_bom.domain.finding_rehydrate import finding_from_dict
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability


def _unscored() -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(id="CVE-2022-0235", summary="s", severity=Severity.HIGH, cvss_score=8.8, fixed_version="2.6.7"),
        package=Package(name="node-fetch", version="2.6.1", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


def _report() -> AIBOMReport:
    return AIBOMReport(agents=[], blast_radii=[_unscored()])


def test_unscored_blast_radius_has_no_risk_score():
    br = _unscored()
    assert br.risk_score is None
    br.calculate_risk_score()
    assert isinstance(br.risk_score, float)


def test_rehydrated_null_risk_cve_row_renders_in_the_attack_flow():
    from agent_bom.output.graph import build_attack_flow_elements

    finding = finding_from_dict(
        {
            "finding_type": "CVE",
            "cve_id": "CVE-2022-0235",
            "title": "CVE-2022-0235: node-fetch@2.6.1",
            "severity": "high",
            "risk_score": None,
        }
    )
    assert finding is not None and finding.risk_score is None
    report = AIBOMReport(agents=[])
    report.findings = [finding]
    elements = build_attack_flow_elements(report)
    tips = [element["data"].get("tip", "") for element in elements if element["data"].get("type") == "cve"]
    assert tips and all("Blast score: not assessed" in tip for tip in tips)


def test_json_reports_unscored_risk_as_null():
    from agent_bom.output.json_fmt import to_json

    payload = to_json(_report())
    rows = [row for row in payload["blast_radius"] if row.get("vulnerability_id") == "CVE-2022-0235"]
    assert rows and all(row["risk_score"] is None for row in rows)
    cve = [row for row in payload["findings"] if row.get("cve_id") == "CVE-2022-0235"]
    assert all(row["risk_score"] is None for row in cve)


def test_sarif_marks_unscored_risk_not_assessed():
    from agent_bom.output.sarif import to_sarif

    results = [result for run in to_sarif(_report())["runs"] for result in run["results"]]
    assert results
    for result in results:
        props = result.get("properties", {})
        assert props.get("blast_score") is None and props.get("risk_score") is None
        assert props.get("risk_score_status") == "not_assessed"


@pytest.mark.parametrize("render", ["csv", "html", "prometheus", "markdown"])
def test_text_outputs_render_unscored_risk_without_a_zero_score(render):
    from agent_bom import output

    text = {
        "csv": lambda: output.to_csv(_report()),
        "html": lambda: output.to_html(_report()),
        "prometheus": lambda: output.to_prometheus(_report()),
        "markdown": lambda: output.to_markdown(_report()),
    }[render]()
    assert "CVE-2022-0235" in text or render == "prometheus"
    if render == "prometheus":
        assert 'blast_radius_score{vuln_id="CVE-2022-0235"' not in text


def test_policy_risk_gate_scores_an_unassessed_blast_radius_instead_of_skipping_it():
    from agent_bom.policy import evaluate_expression

    score = _unscored().calculate_risk_score()
    assert score > 0
    for threshold in (score - 0.5, score + 0.5):
        assert evaluate_expression(f"risk_score >= {threshold}", _unscored()) is (score >= threshold)
        assert evaluate_expression(f"not risk_score >= {threshold}", _unscored()) is (score < threshold)
    assert evaluate_expression("severity >= HIGH", _unscored()) is True


def test_html_cells_say_not_assessed_instead_of_zero():
    from agent_bom import output

    html = output.to_html(_report())
    assert "not assessed" in html


def test_on_demand_consumers_assess_instead_of_reading_zero():
    from agent_bom.cli._remediate import _compute_blast_radius_score

    br = _unscored()
    score = _compute_blast_radius_score([br], "node-fetch")
    assert score > 0 and br.risk_score == score
