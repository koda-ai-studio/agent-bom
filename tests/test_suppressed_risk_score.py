"""A suppressed occurrence keeps its real risk score and says it is suppressed.

Suppression (an approved exception, an ignore entry, operator VEX) is a
decision about the finding, not a re-assessment of its risk. Zeroing the score
made a suppressed critical indistinguishable from an assessed risk of 0. Every
overlay now keeps ``risk_score`` (and ``unsuppressed_risk_score`` for older
readers), sets an explicit ``suppression_state``, and every ranked surface puts
open findings before suppressed ones while open counts exclude them.
"""

from __future__ import annotations

import json

from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from tests._clock_helpers import approvable_expiry


def _blast_radius(cve: str = "CVE-2026-12345", package: str = "requests", risk: float | None = 8.4, **vuln: object) -> BlastRadius:
    server = MCPServer(name="github")
    agent = Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="/tmp/agent.json", mcp_servers=[server])
    return BlastRadius(
        vulnerability=Vulnerability(id=cve, summary="test", severity=Severity.HIGH, **vuln),
        package=Package(name=package, version="2.31.0", ecosystem="pypi"),
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["GITHUB_TOKEN"],
        exposed_tools=[],
        risk_score=risk,
    )


def _store(cve: str = "CVE-2026-12345") -> InMemoryExceptionStore:
    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id=cve,
            package_name="requests",
            server_name="github",
            reason="[finding_feedback:accepted_risk] compensating control",
            requested_by="analyst",
            status=ExceptionStatus.ACTIVE,
            approval_version=1,
            approved_by="admin",
            approved_at="2026-01-01T00:00:00Z",
            expires_at=approvable_expiry(),
            tenant_id="tenant-a",
        ),
        tenant_id="tenant-a",
    )
    return store


def _assert_suppressed_keeps_score(br: BlastRadius, score: float, state: str) -> None:
    assert br.suppressed is True
    assert br.suppression_state == state
    assert br.risk_score == score
    assert br.unsuppressed_risk_score == score
    assert br.is_actionable is False


def test_every_overlay_keeps_the_real_score() -> None:
    from agent_bom.core.vex_policy import apply_vex_suppression
    from agent_bom.ignores import apply_ignores
    from agent_bom.suppression_rules import apply_tenant_suppression_rules

    tenant = _blast_radius()
    apply_tenant_suppression_rules([tenant], _store(), tenant_id="tenant-a")
    _assert_suppressed_keeps_score(tenant, 8.4, "accepted_risk")

    ignored = _blast_radius()
    apply_ignores([ignored], [{"id": "CVE-2026-12345", "reason": "accepted"}])
    _assert_suppressed_keeps_score(ignored, 8.4, "accepted_risk")

    vex = _blast_radius(vex_status="not_affected", vex_source="operator", vex_justification="component_not_present")
    assert apply_vex_suppression(vex) is True
    _assert_suppressed_keeps_score(vex, 8.4, "vex")


def test_scoring_a_suppressed_finding_assesses_it_and_the_score_survives_lifting() -> None:
    from agent_bom.suppression_rules import apply_tenant_suppression_rules

    fresh = _blast_radius(risk=None)
    real = fresh.calculate_risk_score()
    assert real > 0
    suppressed = _blast_radius(risk=None)
    apply_tenant_suppression_rules([suppressed], _store(), tenant_id="tenant-a")
    assert suppressed.risk_score == real
    assert suppressed.calculate_risk_score() == real

    # The exception is gone: the occurrence is open again with the same score.
    apply_tenant_suppression_rules([suppressed], InMemoryExceptionStore(), tenant_id="tenant-a")
    assert suppressed.suppressed is False and suppressed.suppression_state is None
    assert suppressed.risk_score == real


def test_shared_helpers_rank_open_before_suppressed() -> None:
    from agent_bom.core.suppression_score import is_suppressed, open_risk_score, risk_rank_key

    rows = [
        {"id": "low-open", "risk_score": 2.0},
        {"id": "high-suppressed", "risk_score": 9.0, "suppressed": True},
        {"id": "mid-open", "risk_score": 5.0},
        {"id": "unscored", "risk_score": None},
    ]
    assert [row["id"] for row in sorted(rows, key=risk_rank_key)] == ["mid-open", "low-open", "unscored", "high-suppressed"]
    assert open_risk_score(rows[1]) is None and is_suppressed(rows[1])
    assert open_risk_score(rows[0]) == 2.0
    br = _blast_radius()
    br.suppressed = True
    assert is_suppressed(br) and open_risk_score(br) is None


def test_api_row_overlay_keeps_the_score(monkeypatch) -> None:
    from agent_bom.api import finding_suppression

    monkeypatch.setattr(finding_suppression, "_get_exception_store", lambda: _store())
    [row] = finding_suppression.project_current_suppressions(
        [{"vulnerability_id": "CVE-2026-12345", "package_name": "requests", "server_name": "github", "risk_score": 8.4}],
        "tenant-a",
    )
    assert row["suppressed"] is True and row["suppression_state"] == "approved"
    assert row["risk_score"] == 8.4 and row["unsuppressed_risk_score"] == 8.4

    # A persisted row from the old contract (score zeroed) is restored to its real score.
    [legacy] = finding_suppression.project_current_suppressions(
        [
            {
                "vulnerability_id": "CVE-2026-12345",
                "package_name": "requests",
                "server_name": "github",
                "risk_score": 0.0,
                "suppressed": True,
                "unsuppressed_risk_score": 8.4,
            }
        ],
        "tenant-a",
    )
    assert legacy["risk_score"] == 8.4


def _report() -> AIBOMReport:
    from agent_bom.suppression_rules import apply_tenant_suppression_rules

    suppressed = _blast_radius(cve="CVE-2026-12345", risk=9.6)
    apply_tenant_suppression_rules([suppressed], _store(), tenant_id="tenant-a")
    opened = _blast_radius(cve="CVE-2026-22222", package="urllib3", risk=3.1)
    agent = suppressed.affected_agents[0]
    return AIBOMReport(agents=[agent], blast_radii=[suppressed, opened])


def test_sarif_ranks_open_first_and_carries_the_real_suppressed_score() -> None:
    from agent_bom.output.sarif import to_sarif

    sarif = to_sarif(_report())
    results = sarif["runs"][0]["results"]
    cves = [result["ruleId"] for result in results if result["ruleId"].startswith("CVE-")]
    assert cves.index("CVE-2026-22222") < cves.index("CVE-2026-12345")
    suppressed = next(result for result in results if result["ruleId"] == "CVE-2026-12345")
    assert suppressed["suppressions"]
    assert suppressed["properties"]["suppressed"] is True
    assert "0.0" not in json.dumps(suppressed["properties"].get("risk_score", ""))


def test_html_top_risks_rank_open_first_and_label_suppressed() -> None:
    from agent_bom.output import to_html

    html = to_html(_report())
    assert "CVE-2026-22222" in html and "CVE-2026-12345" in html
    assert html.index("CVE-2026-22222") < html.index("CVE-2026-12345")


def test_json_summary_counts_open_only() -> None:
    from agent_bom.output.json_fmt import to_json

    payload = to_json(_report())
    rows = {row["vulnerability_id"]: row for row in payload["blast_radius"]}
    assert rows["CVE-2026-12345"]["risk_score"] == 9.6
    assert rows["CVE-2026-12345"]["suppressed"] is True
