"""Unit tests for the pure parts of the cloud qualification lanes."""

from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

QUALIFICATION = Path(__file__).resolve().parents[1] / "scripts" / "qualification"
sys.path.insert(0, str(QUALIFICATION))

import accuracy  # noqa: E402
import action_check  # noqa: E402
import baseline  # noqa: E402
import common  # noqa: E402
import performance  # noqa: E402
import platforms  # noqa: E402
import summarize  # noqa: E402

WORKFLOW = QUALIFICATION.parents[1] / ".github" / "workflows" / "qualification.yml"


def _report(**overrides) -> dict:
    report = {
        "summary": {"total_agents": 1, "total_mcp_servers": 2, "total_packages": 10, "total_vulnerabilities": 3},
        "finding_summary": {
            "total": 4,
            "by_severity": {"critical": 1, "high": 1, "medium": 2, "low": 0, "unknown": 0},
            "by_type": {"CVE": 3, "COMBINATION": 1},
        },
        "blast_radius": [
            {"vulnerability_id": "CVE-1", "severity": "critical"},
            {"vulnerability_id": "CVE-1", "severity": "critical"},
            {"vulnerability_id": "CVE-2", "severity": "high"},
            {"vulnerability_id": "CVE-3", "severity": "unknown"},
        ],
        "credential_risk_ranking": [{"credential": "API_TOKEN"}],
        "posture_grade": "C",
        "scan_run": {"outcome": "complete"},
    }
    report.update(overrides)
    return report


def test_result_fails_on_failed_check_and_on_defect(tmp_path: Path) -> None:
    ok = common.LaneResult("x", "ok")
    ok.check("a", True)
    ok_exit = ok.write(tmp_path)
    assert ok.passed and ok_exit == 0
    failed = common.LaneResult("x", "bad")
    failed.check("a", False, "why")
    failed_exit = failed.write(tmp_path)
    assert not failed.passed and failed_exit == 1
    defect = common.LaneResult("x", "defect")
    defect.check("a", True)
    defect.defect("D1", "broken", "run it")
    assert not defect.passed
    assert json.loads((tmp_path / "x-bad.json").read_text())["checks"][0]["detail"] == "why"


def test_results_never_publish_an_api_key(tmp_path: Path, capsys) -> None:
    key = "abom_" + "x1-_" * 8
    result = common.LaneResult("x", "key")
    result.check("login", True, f'HTTP 201 {{"raw_key":"{key}"}}')
    result.write(tmp_path)
    assert key not in (tmp_path / "x-key.json").read_text()
    assert key not in capsys.readouterr().out


def test_result_with_no_checks_is_not_a_pass() -> None:
    assert not common.LaneResult("x").passed


def test_percentile_is_nearest_rank_and_handles_empty() -> None:
    assert common.percentile([], 95) == 0.0
    assert common.percentile([1.0, 2.0, 3.0, 4.0, 100.0], 50) == 3.0
    assert common.percentile([1.0, 2.0, 3.0, 4.0, 100.0], 95) == 100.0
    assert common.latency_summary([])["samples"] == 0


def test_run_measured_reports_exit_code_output_and_memory(tmp_path: Path) -> None:
    result = common.run_measured([sys.executable, "-c", "print('hi'); raise SystemExit(3)"], log_dir=tmp_path)
    assert result.returncode == 3
    assert "hi" in result.stdout
    assert not result.timed_out
    if sys.platform != "win32":
        assert result.peak_rss_mb and result.peak_rss_mb > 1


def test_run_measured_kills_on_timeout(tmp_path: Path) -> None:
    result = common.run_measured([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5, log_dir=tmp_path)
    assert result.timed_out
    assert result.returncode != 0


def test_accuracy_counts_unique_advisories_and_unknown_severity() -> None:
    measured = accuracy.measurements(_report())
    assert measured["packages"] == 10
    assert measured["unique_advisories"] == 3
    assert measured["advisory_severity"] == {"critical": 1, "high": 1, "unknown": 1}
    assert measured["unknown_severity"] == 1
    assert measured["agents"] == 1
    assert measured["mcp_servers"] == 2
    assert measured["credential_references"] == 1
    assert measured["credential_findings"] == 0
    assert measured["grade"] == "C"
    assert measured["outcome"] == "complete"


def test_accuracy_finds_advisories_through_aliases() -> None:
    report = _report(blast_radius=[{"vulnerability_id": "GHSA-a", "aliases": ["CVE-9"], "severity": "high"}])
    assert accuracy.advisory_ids(report) == {"GHSA-A", "CVE-9"}


@pytest.mark.parametrize(
    ("change", "failed_check"),
    [
        ({"summary": {"total_packages": 0, "total_vulnerabilities": 3}}, "inventory_has_packages"),
        ({"blast_radius": []}, "reports_advisories"),
        ({"posture_grade": ""}, "grade_present"),
        ({"finding_summary": {"total": 9, "by_severity": {"high": 1}}}, "severity_counts_sum_to_total"),
    ],
)
def test_accuracy_structure_checks_catch_bad_reports(change: dict, failed_check: str) -> None:
    target = accuracy.Target(name="t", kind="image", ref="x", sentinels=(), min_packages=1)
    result = common.LaneResult("accuracy", "t")
    accuracy.assert_report(result, target, _report(**change), returncode=1)
    assert failed_check in [item["name"] for item in result.checks if not item["ok"]]


def test_accuracy_sentinel_miss_fails() -> None:
    target = accuracy.Target(name="t", kind="image", ref="x", sentinels=("CVE-404",), min_packages=1)
    result = common.LaneResult("accuracy", "t")
    accuracy.assert_report(result, target, _report(), returncode=1)
    assert "known_advisories_found" in [item["name"] for item in result.checks if not item["ok"]]


def test_accuracy_flags_all_unknown_severity() -> None:
    target = accuracy.Target(name="t", kind="image", ref="x", sentinels=(), min_packages=1)
    result = common.LaneResult("accuracy", "t")
    report = _report(blast_radius=[{"vulnerability_id": "DSA-1", "severity": "unknown"}])
    accuracy.assert_report(result, target, report, returncode=1)
    assert "advisories_have_severity" in [item["name"] for item in result.checks if not item["ok"]]


def test_accuracy_flags_phantom_mcp_and_false_malicious() -> None:
    target = accuracy.Target(
        name="t", kind="repo", ref="x", sentinels=(), min_packages=1, expect_no_mcp_servers=True, known_legitimate=("good",)
    )
    result = common.LaneResult("accuracy", "t")
    finding = {"finding_type": "MALICIOUS_PACKAGE", "evidence": {"package_name": "good"}}
    accuracy.assert_report(result, target, _report(findings=[finding]), returncode=1)
    failed = [item["name"] for item in result.checks if not item["ok"]]
    assert "no_phantom_mcp_servers" in failed
    assert "no_false_malicious_verdicts" in failed


def test_platform_quickstart_names_persistence_defect() -> None:
    result = common.LaneResult("platforms", "x")
    run = common.RunResult(1, 1.0, None, "", "Error: Completed scan could not be verified in the control-plane database.")
    platforms.record_quickstart_defect(result, run, missing_module="zstandard")
    assert result.defects[0]["id"] == "quickstart-run-fails-on-clean-install"
    assert "zstandard" in result.defects[0]["summary"]


def test_platform_quickstart_names_windows_lookup_defect() -> None:
    result = common.LaneResult("platforms", "x")
    run = common.RunResult(1, 1.0, None, "", "Error: Could not locate the 'agent-bom' executable to run the scan.")
    platforms.record_quickstart_defect(result, run, missing_module=None)
    assert result.defects[0]["id"] == "quickstart-run-cannot-find-itself-on-windows"


def test_accuracy_failures_become_named_defects() -> None:
    target = accuracy.Target(name="t", kind="image", ref="img", sentinels=(), min_packages=1)
    result = common.LaneResult("accuracy", "t")
    report = _report(blast_radius=[{"vulnerability_id": "DSA-1", "severity": "unknown"}])
    accuracy.assert_report(result, target, report, returncode=1)
    accuracy.record_defects(result, target)
    assert [defect["id"] for defect in result.defects] == ["advisories-have-no-severity"]
    assert "img" in result.defects[0]["reproduction"]


def test_accuracy_targets_are_pinned_exactly() -> None:
    for target in accuracy.TARGETS.values():
        if target.kind == "repo":
            assert len(target.commit) == 40
        else:
            assert "@sha256:" in target.ref
        assert target.sentinels


def test_summary_renders_each_lane_status_and_defects(tmp_path: Path) -> None:
    failing = common.LaneResult("deploy", "helm")
    failing.check("install", False, "no CRD")
    failing.defect("D1", "chart needs CRD", "helm install")
    failing.measurements["seconds"] = 3
    failing.write(tmp_path)
    passing = common.LaneResult("runtime", "proxy")
    passing.check("blocks", True)
    passing.skip("saml", "no path")
    passing.write(tmp_path)
    text = summarize.render(summarize.load(tmp_path))
    assert "| deploy | helm | failed |" in text
    assert "| runtime | proxy | passed |" in text
    assert "D1" in text and "chart needs CRD" in text
    assert "saml" in text and "no path" in text
    assert "install" in text


def test_summary_of_nothing_says_so(tmp_path: Path) -> None:
    assert "No qualification results" in summarize.render(summarize.load(tmp_path))


def test_sarif_validation_accepts_valid_and_rejects_invalid() -> None:
    valid = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "agent-bom", "rules": [{"id": "CVE-1"}]}},
                "results": [
                    {
                        "ruleId": "CVE-1",
                        "message": {"text": "m"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "requirements.txt"}}}],
                    }
                ],
            }
        ],
    }
    assert action_check.sarif_problems(valid) == []
    missing_message = json.loads(json.dumps(valid))
    del missing_message["runs"][0]["results"][0]["message"]
    assert action_check.sarif_problems(missing_message)
    no_location = json.loads(json.dumps(valid))
    no_location["runs"][0]["results"][0]["locations"] = []
    assert action_check.sarif_problems(no_location)


def test_platform_output_assertions_reject_empty_reports() -> None:
    assert platforms.check_report_problems({"summary": {"total_packages": 1, "total_vulnerabilities": 1}, "findings": [{}]}) == []
    assert platforms.check_report_problems({"summary": {"total_packages": 0}}) != []


def test_estate_profiles_are_fixed_and_cover_the_audited_size() -> None:
    names = [profile.name for profile in performance.ESTATES]
    assert "audited-1169-findings" in names
    audited = next(profile for profile in performance.ESTATES if profile.name == "audited-1169-findings")
    report, _summary = performance.generate(audited)
    assert len(report["blast_radius"]) == 1008


def test_scale_steps_reach_one_million() -> None:
    assert performance.SCALE_STEPS[-1] == 1_000_000
    assert list(performance.SCALE_STEPS) == sorted(performance.SCALE_STEPS)


def test_scale_runner_records_largest_size_and_why_it_stopped() -> None:
    ingested: list[int] = []

    def ingest(start: int, size: int) -> tuple[bool, str]:
        ingested.append(size)
        return (start < 20, "HTTP 503" if start >= 20 else "")

    outcome = performance.scale_up(ingest, lambda total: {"total": total}, steps=(10, 40, 100), batch=10, budget_seconds=60)
    assert outcome["largest_reached"] == 20
    assert outcome["target"] == 100
    assert outcome["reached_target"] is False
    assert "HTTP 503" in outcome["stop_reason"]
    assert [row["findings"] for row in outcome["steps"]] == [10]


def test_scale_runner_stops_at_time_budget_without_claiming_target() -> None:
    outcome = performance.scale_up(lambda start, size: (True, ""), lambda total: {}, steps=(10, 20), batch=10, budget_seconds=0)
    assert outcome["reached_target"] is False
    assert "budget" in outcome["stop_reason"]


def test_baseline_compare_flags_only_beyond_tolerance() -> None:
    base = {"tolerance": 2.0, "metrics": {"performance/sqlite/graph_p95_ms": 100.0, "performance/sqlite/ingest_seconds": 10.0}}
    measured = {"performance/sqlite/graph_p95_ms": 190.0, "performance/sqlite/ingest_seconds": 25.0, "new/metric": 1.0}
    regressions, missing = baseline.compare(base, measured)
    assert [row["metric"] for row in regressions] == ["performance/sqlite/ingest_seconds"]
    assert missing == []
    regressions, missing = baseline.compare(base, {"performance/sqlite/graph_p95_ms": 1.0})
    assert regressions == []
    assert missing == ["performance/sqlite/ingest_seconds"]


def test_latency_slack_only_widens_small_latency_budgets() -> None:
    base = {
        "tolerance": 2.0,
        "latency_slack_ms": 150,
        "metrics": {"small_p95_ms": 33.0, "large_p95_ms": 900.0, "ingest_seconds": 1.0},
    }
    assert baseline.compare(base, {"small_p95_ms": 146.0, "large_p95_ms": 900.0, "ingest_seconds": 1.0}) == ([], [])
    regressions, _missing = baseline.compare(base, {"small_p95_ms": 184.0, "large_p95_ms": 1801.0, "ingest_seconds": 2.1})
    assert sorted(row["metric"] for row in regressions) == ["ingest_seconds", "large_p95_ms", "small_p95_ms"]


def test_baseline_extract_reads_lane_metrics(tmp_path: Path) -> None:
    lane = common.LaneResult("performance", "sqlite")
    lane.check("ok", True)
    lane.measurements["estates"] = {
        "small": {
            "ingest_status": "stored",
            "ingest_seconds": 1.5,
            "graph": {"p95_ms": 9.0},
            "findings": {"p95_ms": 4.0},
            "api_peak_rss_mb": 300,
        }
    }
    lane.write(tmp_path)
    metrics = baseline.extract(tmp_path)
    assert metrics["performance/sqlite/small/ingest_seconds"] == 1.5
    assert metrics["performance/sqlite/small/graph_p95_ms"] == 9.0
    assert metrics["performance/sqlite/small/findings_p95_ms"] == 4.0
    assert metrics["performance/sqlite/small/api_peak_rss_mb"] == 300


def test_baseline_ignores_unfinished_estates_and_unreached_scale(tmp_path: Path) -> None:
    lane = common.LaneResult("performance", "sqlite")
    lane.check("ok", True)
    lane.measurements["estates"] = {
        "done": {"ingest_status": "stored", "ingest_seconds": 1.0},
        "probe": {"ingest_status": "timed_out", "ingest_seconds": 600.0},
    }
    lane.measurements["scale"] = {"reached_target": False, "elapsed_seconds": 1500.0, "steps": []}
    lane.write(tmp_path)
    assert baseline.extract(tmp_path) == {"performance/sqlite/done/ingest_seconds": 1.0}


def test_committed_baseline_states_its_source_and_margin() -> None:
    document = json.loads(baseline.BASELINE_PATH.read_text(encoding="utf-8"))
    assert document["source"].startswith("runs ")
    assert document["tolerance"] > 1
    assert document["tolerance_reason"]
    assert all(value > 0 for value in document["metrics"].values())
    assert {key.split("/")[0] for key in document["metrics"]} == {"accuracy", "performance"}


def test_workflow_is_manual_and_path_limited_with_read_only_permissions() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = workflow[True]
    assert set(triggers) == {"workflow_dispatch", "pull_request"}
    assert set(triggers["pull_request"]["paths"]) == {".github/workflows/qualification.yml", "scripts/qualification/**"}
    assert "lanes" in triggers["workflow_dispatch"]["inputs"]
    assert workflow["permissions"] == {"contents": "read"}


def test_workflow_jobs_are_bounded_hosted_and_use_no_secrets() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text
    workflow = yaml.safe_load(text)
    for name, job in workflow["jobs"].items():
        assert job.get("timeout-minutes"), name
        strategy = job.get("strategy")
        if strategy:
            assert strategy["fail-fast"] is False, name
        for step in job["steps"]:
            uses = step.get("uses", "")
            if uses and not uses.startswith("./"):
                assert len(uses.split("@")[1]) == 40, uses


def test_workflow_has_all_seven_lanes() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert {"accuracy", "performance", "platforms", "action", "identity", "runtime", "deploy"} <= set(workflow["jobs"])
    assert workflow["jobs"]["platforms"]["strategy"]["matrix"]["os"] == ["ubuntu-latest", "windows-latest", "macos-latest"]


def test_realm_archive_is_readable_only_by_keycloak_and_holds_the_document() -> None:
    import identity

    with tarfile.open(fileobj=io.BytesIO(identity.realm_archive({"realm": "x"}))) as archive:
        member = archive.getmember("import/realm.json")
        assert member.mode == 0o600 and member.uid == identity.KEYCLOAK_UID
        assert json.loads(archive.extractfile(member).read()) == {"realm": "x"}


def _ingest_outcome(monkeypatch, answers: list[tuple[int, dict]]) -> dict:
    import performance

    replies = iter(answers)
    monkeypatch.setattr(performance, "http_json", lambda *_args, **_kwargs: (*next(replies), 0))
    monkeypatch.setattr(performance.time, "sleep", lambda _seconds: None)
    server = type("Server", (), {"base": "http://api", "headers": {}})()
    return performance.push_estate(server, {"scan_id": "s"})


def test_ingest_poll_keeps_its_job_through_overload_and_records_the_retries(monkeypatch) -> None:
    outcome = _ingest_outcome(
        monkeypatch,
        [
            (202, {"job_id": "j", "status": "queued"}),
            (503, {"detail": "busy"}),
            (429, {"detail": "slow"}),
            (200, {"status": "stored", "job_id": "j"}),
        ],
    )
    assert outcome["ingest_status"] == "stored"
    assert outcome["job_id"] == "j"
    assert outcome["poll_retries"] == {"503": 1, "429": 1}


def test_ingest_poll_refusal_says_why(monkeypatch) -> None:
    outcome = _ingest_outcome(monkeypatch, [(202, {"job_id": "j", "status": "queued"}), (404, {"detail": "no such job"})])
    assert outcome["ingest_status"] == "poll_refused"
    assert "HTTP 404" in outcome["detail"] and "no such job" in outcome["detail"]
