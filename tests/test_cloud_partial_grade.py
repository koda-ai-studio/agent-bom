"""Partial cloud grades: score = pass / (pass + fail + unknown), honest coverage label."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.api.posture_recompute import compute_posture_scorecard_from_result
from agent_bom.evidence.cloud_posture import MIN_CONTROL_COVERAGE, PARTIAL_GRADE_CAP, CloudPosture, serialized_cloud_posture
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.posture import compute_posture_scorecard


def _run(outcome, source):
    from agent_bom.evidence.scan_run import ScanIssue, ScanRun

    return ScanRun(outcome=outcome, issues=[ScanIssue(code="collector_failed", stage="discovery", source=source, message="fixture")])


def statuses(*, passed=0, failed=0, error=0, no_data=0, not_applicable=0):
    return ["pass"] * passed + ["fail"] * failed + ["error"] * error + ["no_data"] * no_data + ["not_applicable"] * not_applicable


def cloud_report(**counts):
    report = AIBOMReport(agents=[])
    report.cis_benchmark_data = {"checks": [{"check_id": str(i), "status": s} for i, s in enumerate(statuses(**counts))]}
    return report


def local_report():
    return AIBOMReport(
        agents=[
            Agent(
                name="fixture",
                agent_type=AgentType.CUSTOM,
                config_path="fixture.json",
                mcp_servers=[
                    MCPServer(name="fixture", registry_verified=True, packages=[Package(name="fixture", version="1.0.0", ecosystem="npm")])
                ],
            )
        ]
    )


def test_real_shape_failing_account_grades_f_with_coverage_label():
    card = compute_posture_scorecard(cloud_report(passed=15, failed=39, error=1, no_data=1, not_applicable=3))
    assert card.grade == "F"
    assert card.score == round(100 * 15 / (15 + 39 + 1), 1) == 27.3
    assert card.partial is True
    assert card.no_data is False
    assert card.grade_label == "F (partial, 54 of 56 evaluated)"
    assert card.to_dict()["cloud_controls"] == {
        "passed": 15,
        "failed": 39,
        "unknown": 1,
        "no_data": 1,
        "not_applicable": 3,
        "evaluated": 54,
        "applicable": 56,
        "coverage_percent": 96.4,
    }


def test_no_data_and_not_applicable_are_excluded_from_score_but_error_is_not():
    with_excluded = CloudPosture(present=True, passed=8, failed=2, no_data=5, not_applicable=9)
    assert with_excluded.score == 80.0
    with_error = CloudPosture(present=True, passed=8, failed=1, unknown=1)
    assert with_error.score == 80.0
    assert with_error.evaluated == 9
    assert with_error.applicable == 10


def test_clean_full_account_keeps_top_grade_and_is_not_partial():
    card = compute_posture_scorecard(cloud_report(passed=50, not_applicable=4))
    assert (card.grade, card.score, card.partial) == ("A", 100.0, False)
    assert card.grade_label == "A"
    assert "partial" not in card.summary.lower()


def test_clean_partial_account_is_capped_below_a_with_honest_score():
    card = compute_posture_scorecard(cloud_report(passed=50, no_data=2))
    assert card.score == 100.0
    assert card.grade == PARTIAL_GRADE_CAP == "B"
    assert card.grade_label == "B (partial, 50 of 52 evaluated)"
    assert card.partial is True


def test_grade_cap_respects_adopter_thresholds_but_never_raises_a_lower_grade():
    strict = {"A": 99, "B": 95, "C": 90, "D": 85}
    card = compute_posture_scorecard(cloud_report(passed=46, failed=4, no_data=2), grade_thresholds=strict)
    assert card.score == 92.0
    assert card.grade == "C"


def test_mostly_failing_partial_differs_from_clean_partial():
    failing = compute_posture_scorecard(cloud_report(passed=5, failed=45, no_data=2))
    clean = compute_posture_scorecard(cloud_report(passed=50, no_data=2))
    assert failing.grade == "F" and clean.grade == "B"
    assert failing.score < clean.score
    assert failing.partial and clean.partial


def test_all_error_has_no_grade_with_reason():
    card = compute_posture_scorecard(cloud_report(error=20))
    assert (card.grade, card.no_data, card.partial) == ("N/A", True, False)
    assert card.grade_label == "N/A"
    assert "No cloud controls were evaluated" in card.summary


def test_all_no_data_and_all_not_applicable_have_no_grade():
    for counts in ({"no_data": 20}, {"not_applicable": 20}):
        card = compute_posture_scorecard(cloud_report(**counts))
        assert card.grade == "N/A"
        assert card.no_data is True


def test_low_coverage_has_no_grade_and_names_the_minimum():
    assert MIN_CONTROL_COVERAGE == 0.5
    card = compute_posture_scorecard(cloud_report(passed=9, no_data=11))
    assert card.grade == "N/A"
    assert card.no_data is True
    assert "9 of 20" in card.summary and "50%" in card.summary
    at_minimum = compute_posture_scorecard(cloud_report(passed=10, no_data=10))
    assert at_minimum.grade == "B"


def test_collector_failed_has_no_grade():
    report = AIBOMReport(agents=[])
    report.scan_run = _run("failed", "databricks")
    assert compute_posture_scorecard(report).grade == "N/A"


def test_failed_provider_marks_a_mixed_scan_partial_not_clean():
    report = cloud_report(passed=50)
    report.scan_run = _run("partial", "azure")
    card = compute_posture_scorecard(report)
    assert (card.grade, card.partial) == ("B", True)
    assert card.grade_label == "B (partial, 50 of 50 evaluated)"


def test_non_cloud_connector_failure_does_not_touch_a_local_grade():
    baseline = compute_posture_scorecard(local_report())
    report = local_report()
    report.scan_run = _run("partial", "ollama")
    card = compute_posture_scorecard(report)
    assert card.grade == baseline.grade and card.partial is False


def test_local_only_grading_is_unchanged_by_partial_rules():
    card = compute_posture_scorecard(local_report())
    assert card.partial is False
    assert card.grade_label == card.grade
    assert card.to_dict()["cloud_controls"] is None
    assert "Cloud" not in card.summary


def test_partial_cloud_caps_mixed_scan_grade_and_rate():
    report = local_report()
    report.cis_benchmark_data = {"checks": [{"status": "pass"}] * 9 + [{"status": "no_data"}]}
    card = compute_posture_scorecard(report)
    assert card.partial is True
    assert card.grade != "A"


def test_unrecognized_status_counts_as_unknown_never_as_excluded():
    report = AIBOMReport(agents=[])
    report.cis_benchmark_data = {"checks": [{"status": "pass"}, {"status": "mystery"}]}
    card = compute_posture_scorecard(report)
    assert card.score == 50.0
    assert card.partial is True


@pytest.mark.parametrize(
    "counts",
    [
        {"passed": 50, "not_applicable": 4},
        {"passed": 50, "no_data": 2},
        {"passed": 15, "failed": 39, "error": 1, "no_data": 1, "not_applicable": 3},
        {"error": 5},
        {"passed": 1, "no_data": 9},
    ],
)
def test_pushed_report_grades_identically(counts):
    report = cloud_report(**counts)
    pushed = compute_posture_scorecard_from_result({"agents": [], "cis_benchmark": report.cis_benchmark_data})
    assert pushed.to_dict() == compute_posture_scorecard(report).to_dict()


def test_summary_counters_cannot_overrule_rows_on_coverage():
    report = cloud_report(passed=1, no_data=9)
    report.cis_benchmark_data.update(passed=100, no_data=0)
    assert compute_posture_scorecard(report).grade == "N/A"


def test_incomplete_serialized_issue_only_marks_partial():
    result = {
        "cis_benchmark": {"checks": [{"status": "pass"}]},
        "scan_run": {"issues": [{"code": "cloud_collection_incomplete", "affects_coverage": True}]},
    }
    cloud = serialized_cloud_posture(result)
    assert cloud.partial is True and cloud.gradeable is True


def _job(job_id, result):
    from agent_bom.api.models import JobStatus

    stamp = f"2026-11-04T00:00:0{job_id}Z"
    return SimpleNamespace(
        job_id=str(job_id),
        result=result,
        status=JobStatus.DONE,
        created_at=stamp,
        completed_at=stamp,
        child_job_ids=[],
        request={"inventory": str(job_id)},
    )


def test_tenant_snapshot_matches_cli_on_same_data():
    from agent_bom.api.overview_projection import _posture_snapshot

    report = cloud_report(passed=15, failed=39, error=1, no_data=1, not_applicable=3)
    card = compute_posture_scorecard(report)
    snapshot = _posture_snapshot([_job(0, {"cis_benchmark": report.cis_benchmark_data, "posture_scorecard": card.to_dict()})])
    assert snapshot["grade"] == card.grade
    assert snapshot["score"] == card.score
    assert snapshot["grade_label"] == card.grade_label
    assert snapshot["partial"] is True
    assert snapshot["cloud_controls"] == card.to_dict()["cloud_controls"]


def test_tenant_snapshot_regrades_old_stored_na_scorecards_from_rows():
    from agent_bom.api.overview_projection import _posture_snapshot

    report = cloud_report(passed=15, failed=39, error=1, no_data=1, not_applicable=3)
    stored = {"cis_benchmark": report.cis_benchmark_data, "posture_scorecard": {"grade": "N/A", "score": 0, "no_data": True}}
    snapshot = _posture_snapshot([_job(0, stored)])
    assert snapshot["grade"] == "F" and snapshot["partial"] is True and "no_data" not in snapshot


def test_tenant_snapshot_caps_a_stale_a_from_another_scope():
    from agent_bom.api.overview_projection import _posture_snapshot

    cloud = {"cis_benchmark": {"checks": [{"status": "pass"}, {"status": "pass"}, {"status": "no_data"}]}, "posture_scorecard": {}}
    local = {"posture_scorecard": {"grade": "A", "score": 100}}
    snapshot = _posture_snapshot([_job(0, cloud), _job(1, local)])
    assert snapshot["grade"] == "B"
    assert snapshot["grade_label"] == "B (partial, 2 of 3 evaluated)"


def test_tenant_snapshot_low_coverage_is_ungraded_with_reason():
    from agent_bom.api.overview_projection import _posture_snapshot

    report = cloud_report(passed=1, no_data=9)
    snapshot = _posture_snapshot([_job(0, {"cis_benchmark": report.cis_benchmark_data, "posture_scorecard": {}})])
    assert snapshot["grade"] == "N/A" and snapshot["no_data"] is True
    assert "1 of 10" in snapshot["summary"]


def test_exec_posture_keeps_partial_cap_label_and_cli_parity():
    from agent_bom.api.exec_posture import tenant_exec_posture

    clean = compute_posture_scorecard(cloud_report(passed=50, no_data=2)).to_dict()
    result = tenant_exec_posture("partial-clean", clean, {}, {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0})
    assert result["grade"] == "B"
    assert result["score"] == 100.0
    assert result["partial"] is True
    assert result["grade_label"] == "B (partial, 50 of 52 evaluated)"
    assert "Grade A" not in str(result.get("display"))
    assert "No open findings" not in result["summary"] or "partial" in result["summary"].lower()


def test_exec_posture_cloud_only_headline_is_the_control_pass_rate():
    from agent_bom.api.exec_posture import tenant_exec_posture

    card = compute_posture_scorecard(cloud_report(passed=15, failed=39, error=1, no_data=1, not_applicable=3)).to_dict()
    many_counts = {"critical": 20, "high": 19, "medium": 0, "low": 0, "unrated": 0}
    result = tenant_exec_posture("partial-failing", card, {}, many_counts)
    assert (result["grade"], result["score"]) == ("F", 27.3)
    assert result["grade_label"] == "F (partial, 54 of 56 evaluated)"


def test_exec_posture_hub_evidence_can_still_lower_a_cloud_only_grade():
    from agent_bom.api.exec_posture import tenant_exec_posture

    card = compute_posture_scorecard(cloud_report(passed=50)).to_dict()
    counts = {"critical": 20, "high": 0, "medium": 0, "low": 0, "unrated": 0}
    result = tenant_exec_posture("hub-low", card, {}, counts, hub_kev=2, hub_failing_frameworks={"cis"})
    assert result["grade"] != "A"


def _outcome_client(tenant, report):
    from datetime import datetime, timezone

    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.store import InMemoryJobStore

    result = {"summary": {}, "cis_benchmark": report.cis_benchmark_data, "posture_scorecard": compute_posture_scorecard(report).to_dict()}
    stamp = datetime.now(timezone.utc).isoformat()
    store = InMemoryJobStore()
    store.put(
        ScanJob(
            job_id=tenant,
            tenant_id=tenant,
            created_at=stamp,
            completed_at=stamp,
            status=JobStatus.DONE,
            request=ScanRequest(),
            result=result,
        )
    )
    return store


@pytest.mark.parametrize(
    "counts,grade,label",
    [
        ({"passed": 15, "failed": 39, "error": 1, "no_data": 1, "not_applicable": 3}, "F", "F (partial, 54 of 56 evaluated)"),
        ({"passed": 50, "no_data": 2}, "B", "B (partial, 50 of 52 evaluated)"),
        ({"passed": 50}, "A", "A"),
        ({"passed": 1, "no_data": 9}, "N/A", "N/A"),
    ],
)
def test_overview_and_posture_api_serve_the_cli_grade_and_label(counts, grade, label):
    from starlette.testclient import TestClient

    from agent_bom.api.routes import overview
    from agent_bom.api.server import app, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    tenant = f"partial-{grade.replace('/', '-')}-{sum(counts.values())}"
    report = cloud_report(**counts)
    set_job_store(_outcome_client(tenant, report))
    overview._reset_overview_cache()
    enable_trusted_proxy_env()
    try:
        with TestClient(app) as client:
            headers = proxy_headers(role="analyst", tenant=tenant)
            over = client.get("/v1/overview", headers=headers)
            posture = client.get("/v1/posture", headers=headers)
        assert over.status_code == posture.status_code == 200
        for body in (over.json()["posture"], posture.json()):
            assert body["grade"] == grade
            assert body["grade_label"] == label
            assert body["partial"] is (label != grade)
        assert over.json()["posture"]["score"] == posture.json()["score"]
    finally:
        disable_trusted_proxy_env()
        set_job_store(InMemoryJobStore())


def test_disabled_api_stays_not_in_use_through_provider_discovery(monkeypatch) -> None:
    """The real discovery path sanitizes warnings, and must keep the not-in-use marker."""
    import types

    from agent_bom import cloud
    from agent_bom.cli.agents._cloud import _split_not_in_use
    from agent_bom.cloud.normalization import ServiceNotInUse

    module = types.SimpleNamespace(discover=lambda **_kwargs: ([], [ServiceNotInUse("GKE API is disabled; recorded as not in use.")]))
    monkeypatch.setattr(cloud.importlib, "import_module", lambda _name: module)

    _agents, warnings = cloud.discover_from_provider("gcp")

    remaining, notices = _split_not_in_use("gcp", warnings)
    assert remaining == []
    assert [notice["code"] for notice in notices] == ["cloud_service_not_in_use"]
