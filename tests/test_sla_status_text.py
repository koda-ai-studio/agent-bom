"""SLA deadlines read as overdue / due-in everywhere, and non-CVE findings get the severity policy."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.cli._brief import render_markdown
from agent_bom.core.sla import SLA_POLICY_SOURCE, annotate_sla_presentation, sla_status_text
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.output.html.sections_summary import _executive_headline_section, _headline_row

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def test_status_text_counts_days_either_side_of_the_deadline() -> None:
    assert sla_status_text("2023-10-04", now=NOW) == "Overdue 1126 days"
    assert sla_status_text("2026-11-10T00:00:00+00:00", now=NOW) == "Due in 7 days"
    assert sla_status_text("2026-11-04T00:00:00+00:00", now=NOW) == "Due in 1 day"
    assert sla_status_text("2026-11-03T12:00:00+00:00", now=NOW) == "Due today"
    assert sla_status_text(None, now=NOW) == "No SLA"
    assert annotate_sla_presentation({"sla_due_at": "2023-10-04"}, now=NOW)["sla_status_text"] == "Overdue 1126 days"


def _combination(first_seen: str | None = None) -> Finding:
    return Finding(
        finding_type=FindingType.COMBINATION,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="cursor", asset_type="agent", identifier="agent:cursor"),
        severity="critical",
        title="AI agent can reach a credential or privileged tool",
        first_seen=first_seen,
    )


def test_non_cve_findings_get_the_severity_policy_from_the_scan_time() -> None:
    assert _headline_row(_combination())["sla_due_at"] is None  # no anchor, no invented date
    row = _headline_row(_combination(), observed_at=NOW)
    assert str(row["sla_due_at"]).startswith("2026-11-10")  # critical = 7 days, same policy as CVEs
    assert str(_headline_row(_combination("2026-10-01T00:00:00+00:00"), observed_at=NOW)["sla_due_at"]).startswith("2026-10-08")


def test_html_headline_shows_due_date_with_status() -> None:
    html = _executive_headline_section([], [_combination()], observed_at=NOW)
    assert "2026-11-10" in html and ("Due in" in html or "Overdue" in html)
    assert "no SLA set" not in html


def test_markdown_brief_shows_sla_status() -> None:
    row = annotate_sla_presentation(
        {
            "vulnerability_id": "CVE-2023-4863",
            "package": "pillow@9.0.0",
            "sla_due_at": "2023-10-04",
            "sla_due_at_source": SLA_POLICY_SOURCE,
            "is_kev": True,
        },
        now=NOW,
    )
    payload = {
        "tenant_id": "t",
        "generated_at": "g",
        "posture": {"summary": "s"},
        "issues": {"total": 1, "critical": 0, "high": 1, "kev": 1},
        "remediation_priorities": [row],
        "exposure_paths": None,
        "compliance": {"overall_status": "fail", "evaluated_controls": 1, "total_controls": 1, "latest_scan": "s", "frameworks": {}},
        "scan_history": {"data_points": []},
        "evidence_boundary": "b",
        "links": {"evidence_pack": "/p"},
    }
    assert "Overdue 1126 days" in render_markdown(payload)
