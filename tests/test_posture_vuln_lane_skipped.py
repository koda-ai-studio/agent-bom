"""A skipped vulnerability lane is "not assessed", never a clean 100."""

from __future__ import annotations

from agent_bom.evidence.scan_run import ScanRun, vulnerability_scan_skipped_issue
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_json
from agent_bom.posture import compute_posture_scorecard


def _report(*, skipped: bool) -> AIBOMReport:
    package = Package(name="requests", version="2.31.0", ecosystem="pypi")
    server = MCPServer(name="srv", command="python", packages=[package])
    agent = Agent(name="agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])
    report = AIBOMReport(agents=[agent], blast_radii=[])
    if skipped:
        report.scan_run = ScanRun(issues=[vulnerability_scan_skipped_issue()])
    return report


def test_skipped_vulnerability_lane_is_not_assessed():
    card = compute_posture_scorecard(_report(skipped=True))
    vuln = card.dimensions["vulnerability_posture"].to_dict()
    exploit = card.dimensions["active_exploitation"].to_dict()
    assert vuln["assessed"] is False and exploit["assessed"] is False
    assert vuln["weighted_score"] == 0 and "not assessed" in vuln["details"].lower()
    assert "No vulnerabilities found" not in card.summary
    assert "not assessed" in card.summary.lower()
    assessed = [d for d in card.dimensions.values() if d.assessed]
    expected = round(sum(d.score * d.weight for d in assessed) / sum(d.weight for d in assessed), 1)
    assert card.score == expected


def test_scanned_clean_lane_stays_assessed():
    card = compute_posture_scorecard(_report(skipped=False))
    assert card.dimensions["vulnerability_posture"].to_dict()["assessed"] is True
    assert card.dimensions["vulnerability_posture"].score == 100.0


def test_serialized_skip_receipt_round_trips_to_not_assessed():
    from agent_bom.api.posture_recompute import compute_posture_scorecard_from_result

    doc = to_json(_report(skipped=True))
    recomputed = compute_posture_scorecard_from_result(doc)
    assert recomputed.dimensions["vulnerability_posture"].assessed is False
    assert recomputed.score == doc["posture_scorecard"]["score"]
