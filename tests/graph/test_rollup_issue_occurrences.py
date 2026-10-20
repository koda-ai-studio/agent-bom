"""A finding node shared by several assets counts one issue per occurrence."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rollup_issues import build_issue_index
from agent_bom.graph.types import EntityType


def test_shared_benchmark_node_contributes_each_recorded_occurrence() -> None:
    graph = UnifiedGraph(scan_id="issues", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="misconfig:cis_benchmark:1.16",
            entity_type=EntityType.MISCONFIGURATION,
            label="CIS 1.16",
            severity="high",
            attributes={"finding_ids_by_asset": {"role:a": ["f-1"], "role:b": ["f-2", "f-3"]}},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="misconfig:iac:x", entity_type=EntityType.MISCONFIGURATION, label="x", severity="low", attributes={"finding_id": "f-9"}
        )
    )
    index = build_issue_index(graph)
    assert index["misconfig:cis_benchmark:1.16"] == ("occurrence:f-1", "occurrence:f-2", "occurrence:f-3")
    assert index["misconfig:iac:x"] == ("occurrence:f-9",)
