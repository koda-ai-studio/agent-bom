"""Native taint flow findings carry severity, CWE and OWASP LLM tags on every surface.

The ``code`` side block, the unified Finding promotion and SARIF (both the
unified exporter and ``scripts/code_scan_json_to_sarif.py``) must agree, so
the five-bug fixture is scored once here and checked on each surface.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from agent_bom.ast_analyzer import analyze_project
from agent_bom.ast_flow_scoring import flow_cwe_ids, flow_owasp_llm_tags, flow_severity, is_security_flow_category
from agent_bom.ast_models import FlowFinding
from agent_bom.finding import ast_flow_dict_to_finding, is_ast_security_flow
from agent_bom.models import AIBOMReport
from agent_bom.output.sarif import to_sarif
from scripts.code_scan_json_to_sarif import convert

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sast_scored"


@pytest.mark.parametrize(
    ("category", "sink", "severity", "cwes"),
    [
        ("tainted_sql_query", "conn.execute", "high", ["CWE-89"]),
        ("sql_string_construction", "conn.execute", "high", ["CWE-89"]),
        ("tainted_command_execution", "subprocess.check_output", "critical", ["CWE-78"]),
        ("command_string_construction", "subprocess.check_output", "high", ["CWE-78"]),
        ("unsafe_deserialization", "pickle.loads", "critical", ["CWE-502"]),
        ("tainted_dynamic_code_execution", "eval", "critical", ["CWE-95"]),
        ("tainted_ssrf_sink", "requests.get", "high", ["CWE-918"]),
        ("js_ts_xss_sink", "innerHTML", "high", ["CWE-79"]),
        ("tainted_path_access", "open", "high", ["CWE-22"]),
        ("tainted_llm_prompt", "client.messages.create", "high", ["CWE-1427"]),
        ("js_ts_dangerous_call", "child_process.exec", "high", ["CWE-78"]),
        ("js_ts_dangerous_call", "eval", "high", ["CWE-95"]),
        ("unguarded_tool_sink", "os.popen", "high", ["CWE-78"]),
        ("go_llm_call", "openai.ChatCompletion", "medium", []),
    ],
)
def test_category_scoring_table(category: str, sink: str, severity: str, cwes: list[str]) -> None:
    assert flow_severity(category) == severity
    assert flow_cwe_ids(category, sink) == cwes


def test_prompt_injection_flows_are_security_flows_tagged_llm01() -> None:
    assert is_security_flow_category("tainted_llm_prompt")
    assert flow_owasp_llm_tags("tainted_llm_prompt") == ["LLM01"]
    assert flow_owasp_llm_tags("tainted_sql_query") == []
    assert not is_security_flow_category("go_llm_call")


def test_flow_finding_scores_itself_and_serialises_the_score() -> None:
    finding = FlowFinding(
        category="tainted_llm_prompt",
        title="t",
        detail="d",
        file_path="app.py",
        line_number=3,
        entrypoint="summarize",
        sink="client.messages.create",
    )
    assert finding.severity == "high"
    assert finding.cwe_ids == ["CWE-1427"]
    explicit = FlowFinding(category="x", title="t", detail="d", file_path="a", line_number=1, entrypoint="e", sink="s", severity="low")
    assert explicit.severity == "low"


def test_promoted_finding_uses_row_score_and_owasp_tag() -> None:
    raw = {
        "category": "tainted_llm_prompt",
        "title": "Untrusted data reaches an LLM invocation",
        "detail": "doc reaches client.messages.create",
        "file": "app.py",
        "line": 40,
        "entrypoint": "summarize",
        "sink": "client.messages.create",
        "severity": "high",
        "cwe_ids": ["CWE-1427"],
    }
    assert is_ast_security_flow(raw)
    finding = ast_flow_dict_to_finding(raw)
    assert finding.severity == "high"
    assert finding.cwe_ids == ["CWE-1427"]
    assert finding.owasp_tags == ["LLM01"]
    legacy = ast_flow_dict_to_finding({k: v for k, v in raw.items() if k not in {"severity", "cwe_ids"}})
    assert (legacy.severity, legacy.cwe_ids) == ("high", ["CWE-1427"])


def _fixture_copy(tmp_path: Path) -> Path:
    target = tmp_path / "proj"
    shutil.copytree(FIXTURE, target)
    return target


def test_five_bug_fixture_rows_are_scored(tmp_path: Path) -> None:
    payload = analyze_project(_fixture_copy(tmp_path)).to_dict()
    rows = payload["flow_findings"]
    assert rows
    by_sink = {(row["category"], row["sink"]) for row in rows}
    assert {
        ("tainted_sql_query", "conn.execute"),
        ("tainted_dynamic_code_execution", "eval"),
        ("tainted_command_execution", "subprocess.check_output"),
        ("unsafe_deserialization", "pickle.loads"),
        ("tainted_llm_prompt", "client.messages.create"),
    } <= by_sink
    for row in rows:
        assert row["severity"] in {"critical", "high", "medium"}, row
        assert isinstance(row["cwe_ids"], list), row
        if is_security_flow_category(row["category"]):
            assert row["cwe_ids"], row
    sarif = convert(payload)
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    for result in sarif["runs"][0]["results"]:
        rule = rules[result["ruleId"]]
        assert float(rule["properties"]["security-severity"]) >= 7.0
        assert any(tag.startswith("CWE-") for tag in rule["properties"]["tags"]), rule["id"]
    assert "CWE-1427" in rules["agent-bom-code-flow/tainted_llm_prompt"]["properties"]["tags"]


def test_five_bug_fixture_reaches_unified_findings_and_sarif(tmp_path: Path) -> None:
    analysis = analyze_project(_fixture_copy(tmp_path)).to_dict()
    report = AIBOMReport(ai_inventory_data={"ast_analysis": analysis}, scan_sources=["ast_analysis"])
    findings = report.to_findings()
    severities = Counter(f.severity for f in findings)
    assert severities["critical"] >= 3  # eval, shell, pickle
    prompt = [f for f in findings if "CWE-1427" in f.cwe_ids]
    assert prompt and prompt[0].owasp_tags == ["LLM01"]
    assert all(f.cwe_ids for f in findings)

    run = to_sarif(report)["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert run["results"]
    for result in run["results"]:
        rule = rules[result["ruleId"]]
        assert float(rule["properties"]["security-severity"]) > 0
        assert result["properties"]["cwe_ids"]
        assert set(result["properties"]["cwe_ids"]) <= set(rule["properties"]["tags"])
    assert json.dumps(run)  # serialisable end to end
