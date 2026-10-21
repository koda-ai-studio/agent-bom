"""The showcase scope's recorded history: deterministic stages with real movement."""

from __future__ import annotations

import copy

from agent_bom.api.trend_comparison import public_trend_point
from agent_bom.api.trend_recording import trend_point_from_scan_result
from agent_bom.demo_estate.showcase_history import history_stages, stage_report


def _row(index: int, *, severity: str = "high", resource_type: str = "bucket") -> dict:
    return {
        "id": f"finding-{index:03d}",
        "finding_id": f"finding-{index:03d}",
        "canonical_id": f"finding-{index:03d}",
        "finding_type": "CIS_FAIL",
        "provider": "aws",
        "severity": severity,
        "title": f"Failed check {index % 7}",
        "first_seen": "2026-08-03T18:05:00+00:00",
        "evidence": {
            "check_id": f"check-{index % 7}",
            "resource_id": f"cloud_resource:aws:{resource_type}:r{index:03d}",
            "resource_name": f"r{index:03d}",
            "resource_type": resource_type,
        },
        "node_id": f"cloud_resource:aws:{resource_type}:r{index:03d}",
        "asset": {"name": f"r{index:03d}", "asset_type": "cloud_resource", "canonical_id": f"asset-{index:03d}"},
    }


def _report(count: int = 400) -> dict:
    vuln = {"id": "vuln-1", "vulnerability_id": "CVE-2020-14343", "severity": "critical", "package": "pyyaml@5.3"}
    findings = [vuln, *(_row(i, severity=("critical", "high", "medium")[i % 3]) for i in range(count))]
    return {
        "scan_id": "showcase",
        "generated_at": "2026-10-20T22:45:48+00:00",
        "scan_run": {"scan_id": "showcase", "outcome": "complete", "scopes": [], "issues": []},
        "scan_sources": ["demo", "demo-estate"],
        "posture_scorecard": {"grade": "C", "score": 60},
        "findings": findings,
    }


def _ids(report: dict) -> set[str]:
    return {row["id"] for row in report["findings"]}


def _open_ids(report: dict) -> set[str]:
    return {row["id"] for row in report["findings"] if not row.get("suppressed")}


def test_history_has_at_least_five_dated_stages_ending_at_the_showcase_scan() -> None:
    from agent_bom.demo_estate.showcase_constants import (
        SHOWCASE_BASELINE_CREATED_AT,
        SHOWCASE_BASELINE_SCAN_ID,
        SHOWCASE_CURRENT_CREATED_AT,
        SHOWCASE_SCAN_ID,
    )

    stages = history_stages()
    assert len(stages) >= 5
    assert (stages[-1].scan_id, stages[-1].timestamp) == (SHOWCASE_SCAN_ID, SHOWCASE_CURRENT_CREATED_AT)
    assert (stages[-2].scan_id, stages[-2].timestamp) == (SHOWCASE_BASELINE_SCAN_ID, SHOWCASE_BASELINE_CREATED_AT)
    times = [stage.timestamp for stage in stages]
    assert times == sorted(times) and len(set(times)) == len(times)
    assert len({stage.job_id for stage in stages[:-1]}) == len(stages) - 1


def test_final_stage_keeps_every_current_finding_and_dates_late_arrivals() -> None:
    report = _report()
    stages = history_stages()
    final = stage_report(report, len(stages) - 1)
    assert _ids(final) == _ids(report)
    assert not any(row.get("suppressed") for row in final["findings"])
    arrivals = {
        row["id"]: row["first_seen"]
        for row in final["findings"]
        if row.get("first_seen", "2026-08-03T18:05:00+00:00") != "2026-08-03T18:05:00+00:00"
    }
    assert arrivals, "some findings must arrive during the recorded window"
    assert set(arrivals.values()) <= {stage.timestamp for stage in stages[1:]}
    for index, stage in enumerate(stages):
        staged = stage_report(report, index)
        for row in staged["findings"]:
            assert row["id"] not in arrivals or arrivals[row["id"]] <= stage.timestamp
        assert staged["scan_id"] == stage.scan_id
        assert staged["scan_run"]["scan_id"] == stage.scan_id
        # The current scan keeps its own evidence time so it stays the newest job of its scope.
        expected = report["generated_at"] if index == len(stages) - 1 else stage.timestamp
        assert staged["generated_at"] == expected
        assert staged["scan_run"].get("generated_at", report["generated_at"]) == expected
    # The source report is not mutated.
    assert report == _report()


def test_stages_introduce_fix_and_suppress_findings() -> None:
    report = _report()
    stages = history_stages()
    reports = [stage_report(report, index) for index in range(len(stages))]
    introduced = [len(_ids(reports[i]) - _ids(reports[i - 1])) for i in range(1, len(reports))]
    fixed = [len(_ids(reports[i - 1]) - _ids(reports[i])) for i in range(1, len(reports))]
    suppressed = [sum(bool(row.get("suppressed")) for row in staged["findings"]) for staged in reports]
    assert sum(introduced) > 0 and sum(fixed) > 0 and sum(suppressed) > 0
    open_counts = [len(_open_ids(staged)) for staged in reports]
    assert len(set(open_counts)) >= 4, open_counts
    retired = set().union(*(_ids(staged) for staged in reports)) - _ids(report)
    assert retired, "fixed findings existed only in earlier stages"
    for staged in reports:
        for row in staged["findings"]:
            if row.get("suppressed"):
                assert (row["suppression_state"], row["vex_source"], row["vex_suppressed"]) == ("vex", "operator", True)
                assert row["id"] in retired


def test_stage_plan_is_deterministic() -> None:
    report = _report()
    first = [stage_report(copy.deepcopy(report), index) for index in range(len(history_stages()))]
    second = [stage_report(copy.deepcopy(report), index) for index in range(len(history_stages()))]
    assert first == second


def test_a_retired_finding_never_reuses_a_current_check_on_the_same_resource() -> None:
    report = _report()
    current = {(row["evidence"]["check_id"], row["evidence"]["resource_id"]) for row in report["findings"] if "evidence" in row}
    early = stage_report(report, 0)
    retired = [row for row in early["findings"] if row["id"] not in _ids(report)]
    assert retired
    for row in retired:
        assert (row["evidence"]["check_id"], row["evidence"]["resource_id"]) not in current
        assert row["asset"]["name"] == row["evidence"]["resource_name"]


def test_trend_point_carries_posture_basis_issue_counts() -> None:
    report = _report(3)
    issues = {
        "critical": 4,
        "high": 9,
        "medium": 2,
        "low": 1,
        "unrated": 0,
        "total": 16,
        "kev": 1,
        "approximate": False,
        "basis": "issue_groups",
    }
    point = trend_point_from_scan_result(
        report, tenant_id="t1", scan_id="s1", completed_at="2026-10-19T02:00:00+00:00", scope_id="scope", issue_counts=issues
    )
    assert point is not None
    public = public_trend_point(point, None)
    assert public["issues"] == issues
    bare = trend_point_from_scan_result(report, tenant_id="t1", scan_id="s2", completed_at="2026-10-19T02:00:00+00:00", scope_id="scope")
    assert bare is not None
    assert public_trend_point(bare, None)["issues"] is None


def test_trend_point_ignores_counts_on_another_basis() -> None:
    occurrences = {"critical": 1, "high": 1, "medium": 0, "low": 0, "unrated": 0, "total": 2, "basis": "finding_occurrences"}
    point = trend_point_from_scan_result(
        _report(3), tenant_id="t1", scan_id="s1", completed_at="2026-10-19T02:00:00+00:00", scope_id="scope", issue_counts=occurrences
    )
    assert point is not None
    assert public_trend_point(point, None)["issues"] is None
