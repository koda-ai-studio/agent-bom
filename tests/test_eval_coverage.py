"""Safety-eval coverage finding: risky agents with no linked safety or red-team eval."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from agent_bom.ai_components.eval_coverage import RULE_ID, agent_risk_signals, eval_coverage_findings
from agent_bom.ai_components.eval_suites import scan_eval_suites
from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.finding import FindingSource, FindingType

_FIXTURES = Path(__file__).parent / "fixtures" / "eval_suites"


def _copy(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    shutil.copytree(_FIXTURES / name, root)
    for staged in root.rglob("*.fixture"):
        staged.rename(staged.with_suffix(""))
    return root


def _inventory(root: Path, components: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    agents = [agent.to_dict() for agent in scan_framework_agents(root)]
    scan = scan_eval_suites(root, framework_agents=agents)
    return {
        "framework_agents": agents,
        "eval_suites": [suite.to_dict() for suite in scan.suites],
        "eval_coverage": scan.coverage,
        "components": components or [],
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


_WRITE_AGENT = (
    "import os\nfrom langchain.agents import create_agent\nfrom langchain.tools import tool\n\n"
    "KEY = os.getenv('OPENAI_API_KEY')\n\n@tool\ndef delete_record(record_id: str) -> str:\n    return record_id\n\n"
    "agent = create_agent('openai:gpt-4o', tools=[delete_record], name='records_agent')\n"
)


def test_uncovered_agent_with_write_and_exec_tools_gets_a_medium_governance_finding(tmp_path: Path) -> None:
    findings = eval_coverage_findings(_inventory(_copy(tmp_path, "uncovered_agent")))
    [finding] = findings
    assert finding.finding_type is FindingType.EVAL_COVERAGE_GAP
    assert finding.source is FindingSource.EVAL_SCAN
    assert finding.severity == "medium"
    assert finding.asset.asset_type == "agent" and finding.asset.name == "ops_agent"
    assert finding.evidence["rule_id"] == RULE_ID
    signals = finding.evidence["risk_signals"]
    assert set(signals["write_exec_tools"]) == {"run_shell", "write_file"}
    # The agent's own model-provider key is not counted as reach into other systems.
    assert signals["credentials"] == ["OPS_DB_PASSWORD"]
    assert "no safety or red-team eval linked to this agent was found in the scanned project files" in finding.description
    assert "never" not in finding.description.lower()
    assert finding.evidence["searched"]["scope"] == "uncovered_agent"
    assert finding.evidence["searched"]["files_examined"] >= 1
    assert finding.evidence["eval_suites_in_scope"] == {"safety": 0, "quality": 1, "unknown": 0, "unlinked": 1}
    assert finding.remediation_guidance and "red-team" in finding.remediation_guidance
    assert finding.nist_ai_rmf_tags == ["MEASURE-2.6", "MEASURE-2.7"]
    assert finding.cve_id is None and finding.vulnerability_id is None


@pytest.mark.parametrize("fixture", ["promptfoo_redteam", "deepeval_safety"])
def test_agent_covered_by_a_linked_safety_eval_has_no_finding(tmp_path: Path, fixture: str) -> None:
    assert eval_coverage_findings(_inventory(_copy(tmp_path, fixture))) == []


def test_no_finding_when_eval_detection_did_not_run_or_was_partial(tmp_path: Path) -> None:
    inventory = _inventory(_copy(tmp_path, "uncovered_agent"))
    assert eval_coverage_findings({**inventory, "eval_coverage": None}) == []
    legacy = {key: value for key, value in inventory.items() if key not in {"eval_coverage", "eval_suites"}}
    assert eval_coverage_findings(legacy) == []
    partial = {**inventory, "eval_coverage": {**inventory["eval_coverage"], "status": "partial"}}
    assert eval_coverage_findings(partial) == []
    other_scope = {**inventory, "eval_coverage": {**inventory["eval_coverage"], "scopes": ["somewhere-else"]}}
    assert eval_coverage_findings(other_scope) == []


def test_safety_eval_on_the_graph_covers_its_nodes(tmp_path: Path) -> None:
    root = tmp_path / "graph_app"
    _write(
        root / "app.py",
        _WRITE_AGENT + "\nfrom langgraph.graph import START, MessagesState, StateGraph\n\n"
        "builder = StateGraph(MessagesState)\nbuilder.add_node('records_agent', agent)\nbuilder.add_edge(START, 'records_agent')\n"
        "graph = builder.compile()\n",
    )
    assert [f.asset.name for f in eval_coverage_findings(_inventory(root))] == ["records_agent"]
    _write(root / "promptfooconfig.yaml", "targets: ['file://app.py']\nredteam: {plugins: [excessive-agency]}\n")
    assert eval_coverage_findings(_inventory(root)) == []


def test_model_level_and_unlinked_safety_evals_do_not_cover_the_agent_but_are_reported(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    _write(root / "agent.py", _WRITE_AGENT)
    _write(root / "model_eval" / "promptfooconfig.yaml", "providers: ['openai:gpt-4o']\nredteam: {plugins: [pii]}\n")
    _write(root / "free" / "promptfooconfig.yaml", "providers: ['https://example.invalid/chat']\nredteam: {plugins: [harmful]}\n")
    [finding] = eval_coverage_findings(_inventory(root))
    assert finding.severity == "medium"
    assert [suite["file_path"] for suite in finding.evidence["model_level_safety_evals"]] == ["model_eval/promptfooconfig.yaml"]
    assert [suite["file_path"] for suite in finding.evidence["unlinked_safety_evals"]] == ["free/promptfooconfig.yaml"]
    assert "could not be linked" in finding.description


def test_linked_quality_eval_results_attach_as_labelled_evidence(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    _write(root / "agent.py", _WRITE_AGENT)
    _write(
        root / "promptfooconfig.yaml",
        "targets: ['file://agent.py']\ntests:\n  - assert: [{type: contains, value: ok}]\noutputPath: out.json\n",
    )
    _write(root / "out.json", '{"results": {"timestamp": "2026-09-01T00:00:00Z", "stats": {"successes": 9, "failures": 1, "errors": 0}}}')
    [finding] = eval_coverage_findings(_inventory(root))
    [linked] = finding.evidence["linked_evals"]
    assert linked["purpose"] == "quality"
    assert linked["results"] == [
        {
            "source": "promptfoo output file",
            "source_file": "out.json",
            "recorded_at": "2026-09-01T00:00:00Z",
            "passed": 9,
            "failed": 1,
            "errors": 0,
            "pass_rate": 0.9,
        }
    ]


def test_risk_thresholds() -> None:
    def agent(tools: list[str], creds: list[str], file_path: str = "a.py") -> dict[str, Any]:
        return {
            "stable_id": "x",
            "name": "a",
            "file_path": file_path,
            "capabilities": [{"name": name} for name in tools],
            "credential_refs": creds,
        }

    assert agent_risk_signals(agent(["search_docs"], ["OPENAI_API_KEY", "LANGSMITH_API_KEY"]), []).severity is None
    assert agent_risk_signals(agent(["lookup_ticket"], ["STRIPE_SECRET_KEY"]), []).severity == "low"
    assert agent_risk_signals(agent(["execute_query"], []), []).severity == "medium"
    data = agent_risk_signals(agent(["lookup"], []), [{"type": "vector_store", "name": "chromadb", "file": "a.py"}])
    assert (data.severity, data.data_access) == ("low", ["chromadb"])
    assert agent_risk_signals(agent(["lookup"], []), [{"type": "vector_store", "name": "chromadb", "file": "b.py"}]).severity is None


def test_report_stream_carries_the_finding_without_touching_cve_counts_or_the_gate(tmp_path: Path) -> None:
    from agent_bom.cli.agents._post import _gate_findings
    from agent_bom.models import AIBOMReport

    report = AIBOMReport(agents=[], blast_radii=[], ai_inventory_data=_inventory(_copy(tmp_path, "uncovered_agent")))
    rows = [f for f in report.to_findings() if f.finding_type is FindingType.EVAL_COVERAGE_GAP]
    assert len(rows) == 1
    assert report.total_vulnerabilities == 0
    assert not [f for f in _gate_findings(report) if f.finding_type is FindingType.EVAL_COVERAGE_GAP]
    assert [f.id for f in report.to_findings() if f.finding_type is FindingType.EVAL_COVERAGE_GAP] == [rows[0].id]
