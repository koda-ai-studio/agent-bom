"""Eval suites and coverage findings reach the unified graph through the real CLI report."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.output.report_packing import load_report_document

_FIXTURES = Path(__file__).parent / "fixtures" / "eval_suites"
_PINS = "langgraph==1.2.18\nlangchain==1.4.7\n"


def _report(tmp_path: Path, name: str) -> dict[str, Any]:
    root = tmp_path / name
    shutil.copytree(_FIXTURES / name, root)
    for staged in root.rglob("*.fixture"):
        staged.rename(staged.with_suffix(""))
    (root / "requirements.txt").write_text(_PINS, encoding="utf-8")
    out = tmp_path / f"{name}.json"
    args = ["scan", "-p", str(root), "--ai-inventory", str(root), "--offline", "--no-discover", "-f", "json", "-o", str(out)]
    result = CliRunner().invoke(main, args)
    assert out.exists(), result.output
    return load_report_document(json.loads(out.read_text(encoding="utf-8")))


def _edges(graph: Any, relationship: RelationshipType) -> list[Any]:
    return [edge for edge in graph.edges if edge.relationship == relationship]


@pytest.mark.parametrize("fixture", ["promptfoo_redteam", "uncovered_agent"])
def test_eval_suites_become_nodes_linked_to_what_they_evaluate(tmp_path: Path, fixture: str) -> None:
    report = _report(tmp_path, fixture)
    graph = build_unified_graph_from_report(report, scan_id=fixture)
    suites = graph.nodes_by_type(EntityType.EVAL_SUITE)
    assert len(suites) == len(report["ai_inventory"]["eval_suites"]) == 1
    suite = suites[0]
    assert suite.attributes["harness"] in {"promptfoo", "ragas"}
    evaluates = _edges(graph, RelationshipType.EVALUATES)
    spec = relationship_spec(RelationshipType.EVALUATES)
    assert spec is not None
    for edge in evaluates:
        assert spec.allows(graph.nodes[edge.source].entity_type, graph.nodes[edge.target].entity_type)
        assert edge.evidence["source"] == "eval-scan"
    if fixture == "promptfoo_redteam":
        targets = {graph.nodes[edge.target].entity_type for edge in evaluates}
        assert targets == {EntityType.AGENT, EntityType.MODEL}
        assert suite.attributes["purpose"] == "safety"
        assert suite.attributes["results"][0]["pass_rate"] == 0.92
    else:
        assert evaluates == []
        assert suite.attributes["link_status"] == "unlinked"


def test_coverage_finding_hangs_off_the_agent_without_inventing_one(tmp_path: Path) -> None:
    report = _report(tmp_path, "uncovered_agent")
    rows = [row for row in report["findings"] if row["finding_type"] == "EVAL_COVERAGE_GAP"]
    assert len(rows) == 1
    graph = build_unified_graph_from_report(report, scan_id="uncovered")
    node = graph.nodes[rows[0]["finding_node_id"]]
    assert node.entity_type == EntityType.MISCONFIGURATION
    assert node.severity == "medium"
    assert {"MEASURE-2.6", "MEASURE-2.7"} <= set(node.compliance_tags)
    attached = [
        graph.nodes[edge.source if edge.target == node.id else edge.target]
        for edge in graph.edges
        if node.id in (edge.source, edge.target) and edge.relationship in {RelationshipType.AFFECTS, RelationshipType.VULNERABLE_TO}
    ]
    assert [asset.entity_type for asset in attached] == [EntityType.AGENT]
    agents = graph.nodes_by_type(EntityType.AGENT)
    assert not [agent for agent in agents if agent.id.startswith("agent:") and agent.label == "ops_agent"]
    assert all(agent.attributes.get("asset_type") != "agent" for agent in agents)
    # The agent the finding names carries its eval coverage for the agent drill-down.
    assert attached[0].attributes["eval_coverage"]["safety_suites"] == 0


def test_covered_agent_records_its_linked_safety_suite(tmp_path: Path) -> None:
    report = _report(tmp_path, "promptfoo_redteam")
    assert not [row for row in report["findings"] if row["finding_type"] == "EVAL_COVERAGE_GAP"]
    graph = build_unified_graph_from_report(report, scan_id="covered")
    [edge] = [e for e in _edges(graph, RelationshipType.EVALUATES) if graph.nodes[e.target].entity_type == EntityType.AGENT]
    coverage = graph.nodes[edge.target].attributes["eval_coverage"]
    assert coverage["safety_suites"] == 1
    assert coverage["suites"][0]["harness"] == "promptfoo"


def test_architecture_agent_rows_carry_eval_coverage(tmp_path: Path) -> None:
    from agent_bom.graph.harness_model import HarnessPlacement
    from agent_bom.graph.harness_view import _agent_row, _eval_coverage

    report = _report(tmp_path, "promptfoo_redteam")
    graph = build_unified_graph_from_report(report, scan_id="covered")
    [edge] = [e for e in _edges(graph, RelationshipType.EVALUATES) if graph.nodes[e.target].entity_type == EntityType.AGENT]
    placement = HarnessPlacement(harness_id=edge.target, role="harness", layer=0, entry=True, parent_id="")
    coverage = _agent_row(graph.nodes[edge.target], placement)["eval_coverage"]
    assert (coverage["assessed"], coverage["safety_suites"]) == (True, 1)
    assert coverage["suites"][0]["results"][0]["source_file"] == "results/promptfoo-results.json"
    # No recorded eval search reads as "not assessed", never as "no evals".
    assert _eval_coverage(None) == {"assessed": False, "status": "not_run", "safety_suites": 0, "suites": []}
