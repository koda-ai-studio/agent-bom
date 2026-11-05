"""Exit reasons, scan outcome and every rendered surface for partial cloud grades."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest
from rich.console import Console

from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._post import compute_exit_code
from agent_bom.cloud.aws_cis._base import CheckStatus, CISBenchmarkReport, CISCheckResult
from agent_bom.evidence.scan_run import ScanRun
from agent_bom.models import AIBOMReport


def _check(check_id, status, severity="high"):
    return {
        "check_id": check_id,
        "title": f"Control {check_id}",
        "status": status,
        "severity": severity,
        "cis_section": "1 - Fixture",
        "evidence": "fixture",
        "resource_ids": [],
        "recommendation": "fixture",
    }


def _report(*checks, issues=()):
    report = AIBOMReport(agents=[])
    report.cis_benchmark_data = {"checks": list(checks)}
    report.scan_run = ScanRun(issues=list(issues))
    return report


def _exit(report, *, failures=()):
    con = Console(file=io.StringIO(), width=200, force_terminal=False)
    ctx = ScanContext(con=con)
    ctx.report = report
    ctx.blast_radii = []
    ctx.cloud_provider_failures = list(failures)
    code = compute_exit_code(
        ctx,
        fail_on_severity="high",
        warn_on_severity=None,
        fail_on_kev=False,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=False,
    )
    return code, con.file.getvalue()


def test_exit_reason_leads_with_a_real_failed_control_not_an_errored_check():
    code, out = _exit(_report(_check("1", "error"), _check("2", "fail")))
    assert code == 1
    assert "CIS_FAIL" in out
    assert "CIS_ERROR" not in out


def test_only_errored_checks_exit_nonzero_as_incomplete_not_as_a_finding():
    code, out = _exit(_report(_check("1", "error"), _check("2", "pass")))
    assert code == 1
    assert "CIS_ERROR" not in out
    assert "finding (" not in out
    assert "partial" in out


def test_databricks_error_row_is_not_a_finding_reason_either():
    report = AIBOMReport(agents=[])
    report.databricks_security_data = {"checks": [_check("DBX-1", "error"), _check("DBX-2", "pass")]}
    report.scan_run = ScanRun()
    code, out = _exit(report)
    assert code == 1
    assert "CLOUD_BEST_PRACTICE_ERROR" not in out


def test_clean_complete_cloud_scan_still_exits_zero():
    code, out = _exit(_report(_check("1", "pass")))
    assert code == 0, out


def test_finding_free_posture_never_says_clean_on_partial():
    from agent_bom.output.cis_posture import finding_free_posture

    partial = _report(_check("1", "pass"), _check("2", "no_data"))
    full = _report(_check("1", "pass"))
    assert finding_free_posture(partial)[1] == "PARTIAL COVERAGE"
    assert finding_free_posture(full)[1] == "CLEAN"


def test_compact_grade_line_shows_label_even_at_a_perfect_score():
    from agent_bom.output.compact_rows import posture_grade_line

    line = posture_grade_line(lambda grade: grade, lambda summary: summary, "B", 100.0, "summary", label="B (partial, 50 of 52 evaluated)")
    assert "B (partial, 50 of 52 evaluated)" in line
    assert "100/100" in line


def test_json_report_carries_label_and_keeps_letter_grade():
    from agent_bom.output.json_fmt import to_json

    payload = to_json(_report(*[_check(str(i), "pass") for i in range(9)], _check("n", "no_data")))
    assert payload["posture_grade"] == "B"
    assert payload["posture_grade_label"] == "B (partial, 9 of 10 evaluated)"
    assert payload["posture_scorecard"]["partial"] is True


def test_sarif_run_properties_carry_label():
    from agent_bom.output.sarif_common import _sarif_run_properties

    report = _report(*[_check(str(i), "pass") for i in range(9)], _check("n", "no_data"))
    properties = _sarif_run_properties(report, report.scan_run)
    assert properties["posture_grade"] == "B"
    assert properties["posture_grade_label"] == "B (partial, 9 of 10 evaluated)"


def test_pdf_grade_block_uses_label():
    from agent_bom.output.pdf import _posture_blocks

    report = _report(*[_check(str(i), "pass") for i in range(9)], _check("n", "no_data"))
    text = " ".join(str(getattr(block, "text", "")) for block in _posture_blocks(report, [], []))
    assert "B (partial, 9 of 10 evaluated)" in text
    assert "not graded" not in text


def test_html_report_shows_label_and_no_clean_claim():
    from agent_bom.output.html import to_html

    html = to_html(_report(*[_check(str(i), "pass") for i in range(9)], _check("n", "no_data")), [])
    assert "B (partial, 9 of 10 evaluated)" in html
    assert "NO FINDINGS" not in html


def test_markdown_shows_label_and_withholds_clean_line():
    from agent_bom.output.markdown import to_markdown

    text = to_markdown(_report(*[_check(str(i), "pass") for i in range(9)], _check("n", "no_data")))
    assert "B (partial, 9 of 10 evaluated)" in text
    assert "No vulnerabilities found." not in text


# --- scan outcome: a disabled API or discovery gap with evaluated rows is partial -----------------


class _Empty(SimpleNamespace):
    """Scan state with only the cloud fields a test sets; everything else reads as empty."""

    def __getattr__(self, name):
        return []


def _state(benchmark=None, failures=(), successes=(), warnings=(), notices=()):
    ctx = _Empty(
        cloud_provider_failures=list(failures),
        cloud_provider_successes=list(successes),
        cloud_provider_warnings=list(warnings),
        scan_notices=list(notices),
        cis_benchmark_report=None,
        azure_cis_benchmark_report=None,
        gcp_cis_benchmark_report=benchmark,
        sf_cis_benchmark_report=None,
        databricks_security_report=None,
    )
    return _Empty(ctx=ctx, agents=[], metadata_enrichment=None)


def _gcp_benchmark(*statuses):
    return CISBenchmarkReport(
        checks=[CISCheckResult(check_id=str(i), title="t", status=s, severity="high") for i, s in enumerate(statuses)]
    )


def _collect(st):
    from agent_bom.cli.agents.scan_pipeline.report import _collect_cloud_scopes, _collect_scan_issues

    opts = SimpleNamespace(no_scan=False)
    _collect_scan_issues(opts, st)
    _collect_cloud_scopes(opts, st)
    return st


def test_gcp_with_evaluated_controls_is_partial_not_failed_when_discovery_found_nothing():
    failure = {"provider": "gcp", "stage": "discovery", "error": "Requested cloud collector did not complete."}
    st = _collect(_state(_gcp_benchmark(CheckStatus.PASS, CheckStatus.FAIL), failures=[failure]))
    assert st.scan_outcome.value != "failed"
    scope = next(scope for scope in st.cloud_scopes if scope.name == "cloud:gcp")
    assert scope.status.value == "partial"
    assert scope.message == "Requested cloud collector returned incomplete evidence."


def test_gcp_with_no_evaluated_controls_stays_failed():
    failure = {"provider": "gcp", "stage": "discovery", "error": "Requested cloud collector did not complete."}
    st = _collect(_state(_gcp_benchmark(CheckStatus.NO_DATA), failures=[failure]))
    assert st.scan_outcome.value == "failed"
    assert next(scope for scope in st.cloud_scopes if scope.name == "cloud:gcp").status.value == "unavailable"


def test_gcp_collector_failure_with_no_benchmark_stays_failed():
    failure = {"provider": "gcp", "stage": "discovery", "error": "boom"}
    st = _collect(_state(None, failures=[failure]))
    assert st.scan_outcome.value == "failed"


# --- GCP discovery: a disabled API is recorded as not in use --------------------------------------


class _DisabledApiError(Exception):
    reason = "SERVICE_DISABLED"


class _DeniedError(Exception):
    reason = "IAM_PERMISSION_DENIED"


def test_disabled_gcp_api_is_a_not_in_use_notice_not_a_warning():
    from agent_bom.cloud.normalization import ServiceNotInUse
    from agent_bom.cloud.normalization import service_discovery_gap as _discovery_gap

    gap = _discovery_gap("Cloud Functions", _DisabledApiError("403 API not enabled"))
    assert isinstance(gap, ServiceNotInUse)
    assert "not in use" in gap
    assert not isinstance(_discovery_gap("Cloud Functions", _DeniedError("403 denied")), ServiceNotInUse)


def test_cli_splits_not_in_use_from_real_warnings():
    from agent_bom.cli.agents._cloud import _split_not_in_use
    from agent_bom.cloud.normalization import ServiceNotInUse

    warnings, notices = _split_not_in_use("gcp", ["real problem", ServiceNotInUse("GKE API is disabled; recorded as not in use.")])
    assert warnings == ["real problem"]
    assert notices == [{"code": "cloud_service_not_in_use", "source": "gcp", "message": "GKE API is disabled; recorded as not in use."}]


def test_notice_does_not_affect_coverage_or_outcome():
    st = _collect(
        _state(
            _gcp_benchmark(CheckStatus.PASS),
            successes=[{"provider": "gcp", "stage": "discovery", "item_count": 0}],
            notices=[{"code": "cloud_service_not_in_use", "source": "gcp", "message": "GKE API is disabled; recorded as not in use."}],
        )
    )
    assert st.scan_outcome.value == "complete"
    notice = next(issue for issue in st.scan_issues if issue.code == "cloud_service_not_in_use")
    assert notice.affects_coverage is False
    assert next(scope for scope in st.cloud_scopes if scope.name == "cloud:gcp").status.value == "complete"


@pytest.mark.parametrize("error_type", [_DisabledApiError])
def test_gcp_discover_with_only_disabled_apis_returns_no_real_warnings(monkeypatch, error_type):
    from agent_bom.cli.agents._cloud import _split_not_in_use
    from agent_bom.cloud import gcp

    def disabled(*_args, **_kwargs):
        raise error_type("403 API not enabled")

    for name in ("_discover_vertex_ai", "_discover_cloud_functions", "_discover_gke_clusters", "_discover_cloud_run"):
        monkeypatch.setattr(gcp, name, disabled)
    monkeypatch.setattr(gcp, "attach_envelope_to_agents", lambda *_a, **_k: None)
    monkeypatch.setitem(__import__("sys").modules, "google.cloud.run_v2", SimpleNamespace())
    agents, warnings = gcp.discover(project_id="fixture-project")
    assert agents == []
    real, notices = _split_not_in_use("gcp", warnings)
    assert real == []
    assert len(notices) == 4


def test_errored_databricks_checks_make_the_run_partial():
    from agent_bom.cli.agents.scan_pipeline.helpers import _benchmark_scan_issues
    from agent_bom.cloud.databricks_security import DatabricksSecurityReport

    report = DatabricksSecurityReport(checks=[CISCheckResult(check_id="1", title="t", status=CheckStatus.ERROR, severity="high")])
    issues = _benchmark_scan_issues(SimpleNamespace(databricks_security_report=report))
    assert [(issue.code, issue.source) for issue in issues] == [("benchmark_checks_errored", "databricks")]


def test_report_json_round_trip_is_serializable():
    from agent_bom.output.json_fmt import to_json

    json.dumps(to_json(_report(_check("1", "pass"))), default=str)
