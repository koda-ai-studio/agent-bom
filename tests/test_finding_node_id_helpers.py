"""Misconfiguration node ids come from one helper per finding family."""

from __future__ import annotations

from agent_bom.evidence.finding_node_ids import finding_row_node_id, iac_misconfig_node_id
from agent_bom.graph.asset_entity import _iac_node_ids
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.finding_projection import project_iac


def test_iac_rule_without_an_id_is_unknown_not_none_on_every_path() -> None:
    graph = UnifiedGraph()
    project_iac(graph, {"findings": [{"rule_id": None, "file_path": "main.tf", "line_number": 3, "title": "open SG"}]})

    expected = "misconfig:iac:unknown:main.tf:3"
    assert expected in graph.nodes
    assert iac_misconfig_node_id(None, "main.tf", 3) == expected
    row = {
        "id": "f1",
        "finding_type": "IAC_MISCONFIGURATION",
        "evidence": {"iac": True, "rule_id": None, "file_path": "main.tf", "line_number": 3},
    }
    assert finding_row_node_id(row) == expected

    class _Finding:
        evidence = {"iac": True, "rule_id": None, "file_path": "main.tf", "line_number": 3}

    assert _iac_node_ids(_Finding())[0] == expected
