"""Operator-supplied VEX suppresses; VEX discovered in artifacts stays evidence."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.vex import active_blast_radii, apply_vex, is_vex_suppressed, load_vex

_OPENVEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://example.test/vex/pillow-2023-4863",
    "author": "operator",
    "timestamp": "2026-10-01T00:00:00Z",
    "version": 1,
    "statements": [
        {
            "vulnerability": {"name": "CVE-2023-4863"},
            "products": [{"@id": "pkg:pypi/pillow@9.0.0"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
        }
    ],
}


def _report() -> AIBOMReport:
    webp = Vulnerability(
        id="CVE-2023-4863", summary="libwebp heap overflow", severity=Severity.HIGH, cvss_score=8.8, aliases=["GHSA-j7hp-h8jx-5ppr"]
    )
    other = Vulnerability(id="CVE-2023-50447", summary="pillow eval", severity=Severity.HIGH, cvss_score=8.1)
    pillow = Package(name="pillow", version="9.0.0", ecosystem="pypi", purl="pkg:pypi/pillow@9.0.0", vulnerabilities=[webp, other])
    server = MCPServer(name="srv", command="python", packages=[pillow])
    agent = Agent(name="agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])
    radii = []
    for vuln in (webp, other):
        br = BlastRadius(
            vulnerability=vuln,
            package=pillow,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        )
        br.calculate_risk_score()
        radii.append(br)
    return AIBOMReport(agents=[agent], blast_radii=radii)


def _vex(tmp_path, statement_overrides=None):
    payload = json.loads(json.dumps(_OPENVEX))
    payload["statements"][0].update(statement_overrides or {})
    path = tmp_path / "vex.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_vex(str(path))


def _exit_code(report: AIBOMReport) -> int:
    from agent_bom.cli.agents._post import compute_exit_code

    class _Ctx(SimpleNamespace):
        def __getattr__(self, _name):
            return None

    ctx = _Ctx(con=SimpleNamespace(print=lambda *a, **k: None), blast_radii=report.blast_radii, report=report, policy_passed=True)
    return compute_exit_code(
        ctx,
        fail_on_severity="high",
        warn_on_severity=None,
        fail_on_kev=False,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=True,
    )


def test_operator_vex_suppresses_matching_finding_across_surfaces(tmp_path):
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.output import to_json
    from agent_bom.output.sarif import to_sarif

    report = _report()
    webp_br, other_br = report.blast_radii
    assert apply_vex(report, _vex(tmp_path), source="operator") >= 1

    assert webp_br.vulnerability.vex_source == "operator"
    assert is_vex_suppressed(webp_br.vulnerability)
    assert webp_br.suppressed and webp_br.suppression_state == "vex"
    assert "vulnerable_code_not_in_execute_path" in webp_br.suppression_reason
    assert "https://example.test/vex/pillow-2023-4863" in webp_br.suppression_reason
    assert webp_br.risk_score == 0.0 and webp_br.unsuppressed_risk_score and webp_br.unsuppressed_risk_score > 0
    assert active_blast_radii(report.blast_radii) == [other_br]
    assert not other_br.suppressed

    report.findings = [blast_radius_to_finding(br) for br in report.blast_radii]
    doc = to_json(report)
    rows = {row["vulnerability_id"]: row for row in doc["blast_radius"]}
    assert rows["CVE-2023-4863"]["vex_suppressed"] is True
    assert rows["CVE-2023-4863"]["suppressed"] is True
    assert rows["CVE-2023-4863"]["vex_source"] == "operator"
    assert rows["CVE-2023-50447"]["vex_suppressed"] is False

    sarif = to_sarif(report)
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CVE-2023-4863")
    assert result["suppressions"][0]["kind"] == "external"
    assert "vulnerable_code_not_in_execute_path" in result["suppressions"][0]["justification"]
    other_result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CVE-2023-50447")
    assert "suppressions" not in other_result


def test_operator_vex_drops_out_of_exit_code_gate(tmp_path):
    report = _report()
    report.blast_radii = report.blast_radii[:1]
    assert _exit_code(report) == 1
    apply_vex(report, _vex(tmp_path), source="operator")
    assert _exit_code(report) == 0


def test_discovered_vex_with_same_statement_is_evidence_only(tmp_path):
    report = _report()
    report.blast_radii = report.blast_radii[:1]
    br = report.blast_radii[0]
    score = br.risk_score
    apply_vex(report, _vex(tmp_path))
    assert br.vulnerability.vex_status == "not_affected"
    assert br.vulnerability.vex_source == "discovered"
    assert not is_vex_suppressed(br.vulnerability)
    assert not br.suppressed and br.risk_score == score
    assert active_blast_radii(report.blast_radii) == [br]
    assert _exit_code(report) == 1


@pytest.mark.parametrize("status", ["under_investigation", "affected"])
def test_operator_non_exculpatory_status_never_suppresses(tmp_path, status):
    report = _report()
    overrides = {"status": status, "justification": None}
    if status == "affected":
        overrides["action_statement"] = "upgrade"
    apply_vex(report, _vex(tmp_path, overrides), source="operator")
    assert not any(br.suppressed for br in report.blast_radii)


def test_operator_vex_for_other_product_does_not_suppress(tmp_path):
    report = _report()
    apply_vex(report, _vex(tmp_path, {"products": [{"@id": "pkg:pypi/pillow@10.0.0"}]}), source="operator")
    assert report.blast_radii[0].vulnerability.vex_status is None
    assert not report.blast_radii[0].suppressed


def test_operator_vex_matches_through_ghsa_alias(tmp_path):
    report = _report()
    apply_vex(report, _vex(tmp_path, {"vulnerability": {"name": "GHSA-j7hp-h8jx-5ppr"}}), source="operator")
    assert report.blast_radii[0].suppressed


def test_api_push_projection_counts_operator_vex_suppressed_but_not_discovered():
    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.api.routes.scan import _finding_from_blast_radius

    job = ScanJob(job_id="push", created_at="2026-10-14T00:00:00Z", request=ScanRequest())
    base = {
        "vulnerability_id": "CVE-2023-4863",
        "package": "pillow@9.0.0",
        "severity": "high",
        "risk_score": 0.0,
        "unsuppressed_risk_score": 7.1,
        "vex_status": "not_affected",
        "vex_justification": "vulnerable_code_not_in_execute_path",
    }
    operator = _finding_from_blast_radius({**base, "vex_source": "operator"}, job)
    assert operator["vex_suppressed"] is True and operator["suppressed"] is True
    assert operator["suppression_state"] == "vex"
    discovered = _finding_from_blast_radius({**base, "vex_source": "discovered"}, job)
    assert discovered["vex_suppressed"] is False
    assert not discovered.get("suppressed")


@pytest.mark.parametrize(("source", "excluded"), [("operator", True), (None, True), ("discovered", False)])
def test_graph_applicability_honours_vex_provenance(source, excluded):
    from agent_bom.graph.applicability import aggregate_rows, applicability_from_payload, applicability_from_row

    row = {"vex_status": "not_affected", "vex_justification": "component_not_present", "graph_reachable": True}
    if source:
        row["vex_source"] = source
    assert applicability_from_payload(applicability_from_row(row)).vex_excluded is excluded
    assert aggregate_rows([row]).get("vex_source") == source
