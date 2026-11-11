"""``--serving-endpoint RUNTIME=URL`` wiring through the scan pipeline."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main
from tests._serving_runtime_fixtures import SCENARIOS, serving_fixture


def test_dry_run_lists_each_selected_endpoint_and_read():
    result = CliRunner().invoke(
        main,
        ["scan", "--dry-run", "--serving-endpoint", "vllm=http://127.0.0.1:8000", "--serving-endpoint", "triton=http://127.0.0.1:8001"],
    )
    assert result.exit_code == 0, result.output
    assert "vllm endpoint http://127.0.0.1:8000" in result.output
    assert "/v1/models" in result.output
    assert "triton endpoint http://127.0.0.1:8001" in result.output
    assert "POST /v2/repository/index" in result.output


def test_malformed_and_unknown_runtime_specs_are_usage_errors():
    runner = CliRunner()
    malformed = runner.invoke(main, ["scan", "--dry-run", "--serving-endpoint", "http://127.0.0.1:8000"])
    assert malformed.exit_code == 2
    assert "RUNTIME=URL" in malformed.output
    unknown = runner.invoke(main, ["scan", "--dry-run", "--serving-endpoint", "mystery=http://127.0.0.1:8000"])
    assert unknown.exit_code == 2
    assert "vllm" in unknown.output


def _scan(tmp_path, *endpoints: str) -> dict:
    out = tmp_path / "report.json"
    args = ["scan", "--no-scan", "--quiet", "-f", "json", "-o", str(out)]
    for endpoint in endpoints:
        args += ["--serving-endpoint", endpoint]
    result = CliRunner().invoke(main, args, env={"HOME": str(tmp_path)})
    assert out.exists(), result.output
    return json.loads(out.read_text())


def _serving_agents(report: dict) -> list[dict]:
    return [a for a in report.get("agents", []) if (a.get("metadata") or {}).get("serving_evidence")]


def test_successful_endpoint_reaches_json_report_with_evidence(tmp_path):
    with serving_fixture(SCENARIOS["llamacpp"]["success"]) as url:
        report = _scan(tmp_path, f"llamacpp={url}")
    (agent,) = _serving_agents(report)
    evidence = agent["metadata"]["serving_evidence"]
    assert evidence["runtime"]["name"] == "llamacpp"
    assert evidence["endpoint"]["url"] == url
    assert evidence["collection"]["status"] == "success"


def test_one_failed_endpoint_is_reported_as_failed_beside_a_successful_one(tmp_path):
    with serving_fixture(SCENARIOS["vllm"]["success"]) as ok, serving_fixture(SCENARIOS["vllm"]["denied"]) as denied:
        report = _scan(tmp_path, f"vllm={ok}", f"vllm={denied}")
    assert [a["metadata"]["serving_evidence"]["endpoint"]["url"] for a in _serving_agents(report)] == [ok]
    scan_run = report["scan_run"]
    assert scan_run["outcome"] == "partial"
    issues = [issue for issue in scan_run["issues"] if issue["source"] == "serving"]
    assert {issue["code"] for issue in issues} == {"collector_warning", "collector_failed"}
    assert any("denied" in issue["message"] for issue in issues)
    (scope,) = [scope for scope in scan_run["scopes"] if scope["name"] == "cloud:serving"]
    assert scope["status"] == "partial"
