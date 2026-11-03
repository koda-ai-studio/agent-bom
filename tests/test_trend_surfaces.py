"""Better/worse than the last scan reads the same in the console, HTML report and brief."""

from __future__ import annotations

from agent_bom.cli._brief import brief_trend
from agent_bom.core.trend import trend_direction, trend_sentence
from agent_bom.models import AIBOMReport
from agent_bom.output.html import to_html
from agent_bom.storage import last_scan_summary as memory


def test_direction_compares_new_against_resolved() -> None:
    assert trend_direction(3, 1) == "worse"
    assert trend_direction(0, 2) == "better"
    assert trend_direction(1, 1) == "unchanged"
    assert trend_sentence(3, 1) == "Worse than the last scan: 3 new, 1 resolved."
    assert "partial" in trend_sentence(0, 0, partial=True)


def test_console_delta_line_names_the_direction() -> None:
    change = memory.ScanChange("2026-11-01T10:00:00", new_findings=0, resolved_findings=5, new_servers=0, new_tools=0, partial=False)
    assert "better" in memory.delta_line(change)
    assert memory.trend_payload(change)["direction"] == "better"


def test_html_report_shows_the_trend_only_when_remembered() -> None:
    report = AIBOMReport(agents=[])
    assert "trend-banner" not in to_html(report, [])
    report.since_last_scan = {"previous_at": "2026-11-01T10:00:00", "new": 2, "resolved": 0, "partial": False}
    page = to_html(report, [])
    assert "trend-banner" in page and "Worse than the last scan: 2 new, 0 resolved." in page


def test_brief_trend_uses_only_a_comparable_history_point() -> None:
    comparable = {"scan_history": {"data_points": [{"comparison": {"status": "comparable", "new_findings": 1, "no_longer_detected": 4}}]}}
    assert brief_trend(comparable) == "Trend: Better than the last scan: 1 new, 4 resolved."
    other = {"scan_history": {"data_points": [{"comparison": {"status": "unavailable", "reason": "different_scope"}}]}}
    assert "not comparable" in brief_trend(other) and "different_scope" in brief_trend(other)
    assert "no previous scan" in brief_trend({"scan_history": {"data_points": []}})


def test_since_last_scan_never_reaches_machine_json() -> None:
    from agent_bom.output.json_fmt import to_json

    report = AIBOMReport(agents=[])
    report.since_last_scan = {"previous_at": "x", "new": 1, "resolved": 0}
    assert "since_last_scan" not in to_json(report)
