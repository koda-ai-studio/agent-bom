"""Executive and impact briefs speak in names, labelled units and an honest SLA basis."""

from __future__ import annotations

from agent_bom.api.overview_rollup import _finding_top_risk
from agent_bom.cli._brief import render_markdown
from agent_bom.core.sla import SLA_POLICY_SOURCE, annotate_sla_presentation, sla_policy_label
from agent_bom.output.impact_html import _risk


def test_sla_policy_label_names_the_rule_that_actually_applied() -> None:
    assert sla_policy_label(SLA_POLICY_SOURCE, is_kev=False) == "Severity policy (v1)"
    assert sla_policy_label(SLA_POLICY_SOURCE, is_kev=True) == "CISA KEV due date (v1)"
    assert sla_policy_label("explicit") == "Explicit due date"
    langchain = annotate_sla_presentation(
        {"sla_due_at": "2026-12-01T00:00:00+00:00", "sla_due_at_source": SLA_POLICY_SOURCE, "is_kev": False}
    )
    assert langchain["sla_policy"] == "Severity policy (v1)"
    assert langchain["sla_due_at_source"] == SLA_POLICY_SOURCE  # machine id unchanged


def test_top_risk_rows_carry_a_title_and_component_for_non_cve_findings() -> None:
    row = _finding_top_risk(
        {
            "id": "8c1d6f0e-1111-4222-8333-944455556666",
            "title": "AI agent can reach a credential or privileged tool",
            "severity": "critical",
            "asset": {"name": "cursor → shell-runner-server", "asset_type": "agent"},
        }
    )
    assert row["title"] == "AI agent can reach a credential or privileged tool"
    assert row["component"] == "cursor → shell-runner-server"


def _payload(rows: list[dict]) -> dict:
    return {
        "tenant_id": "default",
        "generated_at": "2026-11-03T00:00:00+00:00",
        "posture": {"summary": "D"},
        "issues": {"total": 337, "critical": 96, "high": 12, "kev": 3, "basis": "issue_groups"},
        "remediation_priorities": rows,
        "exposure_paths": None,
        "compliance": {"overall_status": "fail", "evaluated_controls": 1, "total_controls": 2, "latest_scan": "s", "frameworks": {}},
        "scan_history": {"data_points": []},
        "evidence_boundary": "b",
        "links": {"evidence_pack": "/v1/compliance/report/pack"},
    }


def test_markdown_brief_uses_titles_components_policy_labels_and_units() -> None:
    uuid = "8c1d6f0e-1111-4222-8333-944455556666"
    rows = [
        annotate_sla_presentation(
            {
                "vulnerability_id": uuid,
                "title": "AI agent can reach a credential or privileged tool",
                "component": "cursor",
                "package": None,
                "owner": "secops",
                "sla_due_at": "2026-12-01T00:00:00+00:00",
                "sla_due_at_source": SLA_POLICY_SOURCE,
                "is_kev": False,
            }
        ),
        annotate_sla_presentation(
            {"vulnerability_id": "CVE-2023-4863", "package": "pillow@9.0.0", "sla_due_at_source": SLA_POLICY_SOURCE, "is_kev": True}
        ),
    ]
    text = render_markdown(_payload(rows)).replace("\\", "")
    assert uuid not in text
    assert "AI agent can reach a credential or privileged tool" in text and "| cursor |" in text
    assert "CVE-2023-4863" in text and "pillow@9.0.0" in text
    assert "Severity policy (v1)" in text and "CISA KEV due date (v1)" in text
    assert "severity-kev/v1" not in text
    assert "Not recorded" not in text
    assert "Open issue groups: 337" in text and "issue groups, not finding occurrences" in text


def test_impact_brief_lists_agent_names_and_collapses_ids() -> None:
    ids = [f"agent-{i:02d}-0000-0000" for i in range(12)]
    html = _risk(
        {
            "id": "f1",
            "title": "t",
            "severity": "high",
            "asset_name": "pillow",
            "asset_id": "a1",
            "agent_ids": ids,
            "agent_names": ["cursor", "claude-desktop"],
            "reported_condition": "c",
            "potential_consequence": "p",
            "confidence_basis": "b",
            "recommended_action": "r",
            "owner": "o",
            "receipt_pointer": "/findings/0",
            "receipt": {},
        },
        1,
    )
    assert "cursor, claude-desktop" in html
    assert "<summary>12 linked agent IDs</summary>" in html
    visible = html.split("<summary>12 linked agent IDs</summary>", 1)[0]
    assert ids[0] not in visible
