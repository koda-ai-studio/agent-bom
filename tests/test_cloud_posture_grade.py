"""Cloud controls and collection gaps participate in every scan scorecard."""

from types import SimpleNamespace

import pytest

from agent_bom.api.posture_recompute import compute_posture_scorecard_from_result
from agent_bom.api.tenant_posture_dimensions import current_findings_dimensions
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.posture import compute_posture_scorecard

FIELDS = [
    ("cis_benchmark_data", "cis_benchmark"),
    ("azure_cis_benchmark_data", "azure_cis_benchmark"),
    ("gcp_cis_benchmark_data", "gcp_cis_benchmark"),
    ("snowflake_cis_benchmark_data", "snowflake_cis_benchmark"),
    ("databricks_security_data", "databricks_security"),
]


def report_with(field, statuses, *, local=False):
    report = AIBOMReport(agents=[])
    if local:
        report.agents = [
            Agent(
                name="fixture",
                agent_type=AgentType.CUSTOM,
                config_path="fixture.json",
                mcp_servers=[
                    MCPServer(name="fixture", registry_verified=True, packages=[Package(name="fixture", version="1.0.0", ecosystem="npm")])
                ],
            )
        ]
    setattr(report, field, {"checks": [{"check_id": str(i), "status": s} for i, s in enumerate(statuses)]})
    return report


@pytest.mark.parametrize("field,key", FIELDS)
def test_cloud_only_grade_uses_evaluated_controls_and_preserves_push_parity(field, key):
    report = report_with(field, ["PASS", "FAIL", "FAIL", "NOT_APPLICABLE"])
    score = compute_posture_scorecard(report)
    assert score.grade == "F"
    assert score.score == 33.3
    assert score.dimensions["compliance_coverage"].score == 33.3
    assert not score.dimensions["active_exploitation"].assessed
    assert not score.dimensions["credential_hygiene"].assessed
    pushed = compute_posture_scorecard_from_result({"agents": [], key: getattr(report, field)})
    assert pushed.to_dict() == score.to_dict()


@pytest.mark.parametrize("field,key", FIELDS)
@pytest.mark.parametrize("missing", ["ERROR", "NO_DATA", "unrecognized"])
def test_missing_cloud_evidence_never_inherits_local_passing_grade(field, key, missing):
    report = report_with(field, ["PASS", missing], local=True)
    score = compute_posture_scorecard(report)
    assert score.grade == "N/A"
    assert "Cloud" in score.summary and "incomplete" in score.summary
    assert not score.dimensions["compliance_coverage"].assessed


@pytest.mark.parametrize("statuses", [[], ["NOT_APPLICABLE"]])
def test_no_evaluated_controls_do_not_get_a_grade(statuses):
    assert compute_posture_scorecard(report_with("cis_benchmark_data", statuses, local=True)).grade == "N/A"


def test_failing_cloud_controls_cannot_be_averaged_away_by_local_metadata():
    report = report_with("cis_benchmark_data", ["PASS"] + ["FAIL"] * 9, local=True)
    score = compute_posture_scorecard(report)
    assert score.score <= 10
    assert score.grade == "F"
    assert "9 failed" in score.summary


def test_summary_counters_cannot_overrule_actual_check_statuses():
    report = report_with("cis_benchmark_data", ["FAIL"])
    report.cis_benchmark_data.update(passed=100, failed=0, pass_rate=100)
    assert compute_posture_scorecard(report).score == 0


def test_tenant_dimensions_include_all_current_cloud_controls():
    jobs = [
        SimpleNamespace(job_id="a", result={"cis_benchmark": {"checks": [{"status": "FAIL"}]}}),
        SimpleNamespace(job_id="b", result={"gcp_cis_benchmark": {"checks": [{"status": "PASS"}]}}),
    ]
    dimensions = current_findings_dimensions(jobs, [])["dimensions"]
    assert dimensions["compliance_coverage"]["name"] == "Cloud Control Posture"
    assert dimensions["compliance_coverage"]["score"] == 50
    assert not dimensions["active_exploitation"]["assessed"]


@pytest.mark.parametrize("statuses,expected", [(["PASS"], "A"), (["FAIL"], "F"), (["PASS", "ERROR"], "N/A")])
def test_cloud_scorecard_reaches_overview_and_posture_without_local_artifacts(statuses, expected):
    from datetime import datetime, timezone

    from starlette.testclient import TestClient

    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.routes import overview
    from agent_bom.api.server import app, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    tenant = "cloud-grade-" + expected.replace("/", "-")
    report = report_with("cis_benchmark_data", statuses)
    result = {"summary": {}, "cis_benchmark": report.cis_benchmark_data, "posture_scorecard": compute_posture_scorecard(report).to_dict()}
    stamp = datetime.now(timezone.utc).isoformat()
    store = InMemoryJobStore()
    job = ScanJob(
        job_id=tenant, tenant_id=tenant, created_at=stamp, completed_at=stamp, status=JobStatus.DONE, request=ScanRequest(), result=result
    )
    store.put(job)
    set_job_store(store)
    overview._reset_overview_cache()
    enable_trusted_proxy_env()
    try:
        with TestClient(app) as client:
            headers = proxy_headers(role="analyst", tenant=tenant)
            overview_result = client.get("/v1/overview", headers=headers)
            posture_result = client.get("/v1/posture", headers=headers)
        assert overview_result.status_code == posture_result.status_code == 200
        assert overview_result.json()["posture"]["grade"] == expected
        assert posture_result.json()["grade"] == expected
        assert posture_result.json()["score"] == overview_result.json()["posture"]["score"]
    finally:
        disable_trusted_proxy_env()
        set_job_store(InMemoryJobStore())


@pytest.mark.parametrize("field,key", FIELDS)
def test_partial_benchmark_metadata_prevents_grade_even_when_rows_pass(field, key):
    report = report_with(field, ["PASS"])
    getattr(report, field)["completeness"] = "partial"
    assert compute_posture_scorecard(report).grade == "N/A"


def test_latest_local_scan_cannot_hide_another_current_cloud_scope():
    from agent_bom.api.models import JobStatus
    from agent_bom.api.overview_projection import _posture_snapshot

    jobs = []
    for index, result in enumerate(
        [
            {"cis_benchmark": {"checks": [{"status": "PASS"}, {"status": "NO_DATA"}]}, "posture_scorecard": {"grade": "N/A", "score": 0}},
            {"posture_scorecard": {"grade": "A", "score": 100}},
        ]
    ):
        jobs.append(
            SimpleNamespace(
                job_id=str(index),
                result=result,
                status=JobStatus.DONE,
                created_at=f"2026-11-04T00:00:0{index}Z",
                completed_at=f"2026-11-04T00:00:0{index}Z",
                child_job_ids=[],
                request={"inventory": str(index)},
            )
        )
    snapshot = _posture_snapshot(jobs)
    assert snapshot["grade"] == "N/A"
    assert snapshot["no_data"] is True


def test_partial_cloud_evidence_cannot_regain_grade_from_finding_counts():
    from agent_bom.api.exec_posture import tenant_exec_posture

    result = tenant_exec_posture(
        "cloud-incomplete-counts",
        {"grade": "N/A", "score": 0, "no_data": True, "summary": "Cloud evidence incomplete"},
        {},
        {"critical": 1, "high": 2, "medium": 0, "low": 0, "unrated": 0},
    )
    assert result["grade"] == result["display"] == "N/A"
    assert result["no_data"] is True


def test_failed_cloud_attempt_is_not_hidden_by_previous_healthy_scan():
    from agent_bom.api.models import JobStatus
    from agent_bom.api.overview_projection import _posture_snapshot

    jobs = []
    for index, result in enumerate(
        [
            {"cis_benchmark": {"checks": [{"status": "PASS"}]}, "posture_scorecard": {"grade": "A", "score": 100}},
            {
                "cloud_inventory": [{"provider": "aws", "status": "error"}],
                "scan_run": {"outcome": "failed"},
                "posture_scorecard": {"grade": "N/A", "score": 0, "no_data": True},
            },
        ]
    ):
        jobs.append(
            SimpleNamespace(
                job_id=str(index),
                result=result,
                status=JobStatus.DONE,
                created_at=f"2026-11-04T00:00:0{index}Z",
                completed_at=f"2026-11-04T00:00:0{index}Z",
                child_job_ids=[],
                request={"inventory": "same-cloud-scope"},
            )
        )
    assert _posture_snapshot(jobs)["grade"] == "N/A"


def test_serialized_cloud_collection_issue_preserves_incompleteness():
    from agent_bom.evidence.cloud_posture import serialized_cloud_posture

    result = {
        "cis_benchmark": {"checks": [{"status": "PASS"}]},
        "scan_run": {"issues": [{"code": "cloud_collection_incomplete", "affects_coverage": True}]},
    }
    assert serialized_cloud_posture(result).incomplete is True
