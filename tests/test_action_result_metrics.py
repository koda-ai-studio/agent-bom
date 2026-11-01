"""The GitHub Action reports the grade and counts the report computed, never a recomputed letter."""

from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "action_result_metrics.py"


def _run(monkeypatch, capsys, path: Path, vuln_count: str = "6") -> dict[str, str]:
    monkeypatch.setenv("RESULT_FILE", str(path))
    monkeypatch.setenv("VULN_COUNT", vuln_count)
    runpy.run_path(str(SCRIPT))
    out = capsys.readouterr().out
    return dict(line.split("=", 1) for line in out.strip().splitlines())


def _json_report() -> dict:
    # Seven nested "critical" severities (findings, unified rows, tags) exist so a
    # dict-walk would say 7 / grade F; the report itself says 1 critical path and C.
    rows = [
        {"severity": "critical", "suppressed": False, "exposure_path_id": "blast:cve-2025-6514:npm:mcp-remote:0.1.15"},
        {"severity": "critical", "suppressed": True, "exposure_path_id": "blast:cve-2025-0001:npm:left-pad:1.0.0"},
        {"severity": "high", "suppressed": False},
        {"severity": "high", "suppressed": False},
        {"severity": "medium", "suppressed": False},
    ]
    return {
        "schema_version": "3",
        "summary": {"total_vulnerabilities": 5, "critical_findings": 1, "total_findings": 6},
        "blast_radius": rows,
        "exposure_paths": {"path_count": 5, "suppressed_path_count": 1, "paths": [{"severity": "critical"}] * 6},
        "findings": [{"severity": "critical"}] * 7,
        "posture_scorecard": {"grade": "C", "score": 72.2},
        "posture_grade": "C",
    }


def test_json_report_metrics_come_from_the_report_fields(tmp_path, monkeypatch, capsys):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_json_report()), encoding="utf-8")
    metrics = _run(monkeypatch, capsys, path)
    assert metrics == {"exposure_paths_count": "5", "blast_radius_critical_count": "1", "posture_grade": "C"}


def test_json_report_with_no_gradable_artifacts_reports_the_report_verdict(tmp_path, monkeypatch, capsys):
    document = _json_report()
    document["posture_grade"] = "N/A"
    document["blast_radius"] = []
    document["exposure_paths"] = {"path_count": 0, "paths": []}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    metrics = _run(monkeypatch, capsys, path, vuln_count="0")
    assert metrics == {"exposure_paths_count": "0", "blast_radius_critical_count": "0", "posture_grade": "N/A"}


def test_json_document_without_a_posture_grade_is_unknown_not_recomputed(tmp_path, monkeypatch, capsys):
    path = tmp_path / "skills.json"
    path.write_text(json.dumps({"summary": {"findings": 3}, "findings": [{"severity": "critical"}, {"severity": "low"}]}), encoding="utf-8")
    metrics = _run(monkeypatch, capsys, path, vuln_count="3")
    assert metrics == {"exposure_paths_count": "0", "blast_radius_critical_count": "1", "posture_grade": "unknown"}


def test_sarif_metrics_read_run_properties_and_security_severity(tmp_path, monkeypatch, capsys):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "CVE-2025-6514", "properties": {"security-severity": "9.3"}}]}},
                "results": [
                    {"ruleId": "CVE-2025-6514", "level": "error"},
                    {"ruleId": "CVE-2025-6514", "level": "error", "properties": {"verdict": "possibly_affected"}},
                    {"ruleId": "CVE-2024-29041", "level": "error", "properties": {"security-severity": "7.5"}},
                ],
                "properties": {"scan_outcome": "complete", "posture_grade": "C", "exposure_path_count": 5},
            }
        ]
    }
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    metrics = _run(monkeypatch, capsys, path)
    assert metrics == {"exposure_paths_count": "5", "blast_radius_critical_count": "1", "posture_grade": "C"}


def test_sarif_without_posture_properties_is_unknown(tmp_path, monkeypatch, capsys):
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}), encoding="utf-8")
    metrics = _run(monkeypatch, capsys, path, vuln_count="0")
    assert metrics == {"exposure_paths_count": "0", "blast_radius_critical_count": "0", "posture_grade": "unknown"}


@pytest.mark.parametrize("contents", ["not json", "[1, 2]", ""])
def test_unreadable_or_unshaped_input_is_unknown(tmp_path, monkeypatch, capsys, contents):
    path = tmp_path / "broken.json"
    path.write_text(contents, encoding="utf-8")
    metrics = _run(monkeypatch, capsys, path)
    assert metrics["posture_grade"] == "unknown"


def test_sarif_export_carries_the_same_posture_grade_and_path_count_as_the_json_report():
    from agent_bom import output
    from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability

    vulnerability = Vulnerability(id="CVE-2025-6514", severity=Severity.CRITICAL, summary="Command injection", cvss_score=9.3)
    package = Package(name="mcp-remote", version="0.1.15", ecosystem="npm", vulnerabilities=[vulnerability])
    server = MCPServer(name="remote-bridge", command="npx", args=["-y", "mcp-remote@0.1.15"], packages=[package])
    agent = Agent(name="project:mcpfix", agent_type=AgentType.CUSTOM, config_path="/w/.mcp.json", mcp_servers=[server])
    blast = BlastRadius(
        package=package,
        vulnerability=vulnerability,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[blast])
    document = output.to_json(report)
    run = output.to_sarif(report)["runs"][0]
    assert run["properties"]["posture_grade"] == document["posture_grade"]
    assert run["properties"]["exposure_path_count"] == document["exposure_paths"]["path_count"]
