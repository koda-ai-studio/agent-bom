"""The demo graph reads exposure -> asset -> crown jewel from recorded sample facts."""

from __future__ import annotations

from functools import lru_cache

from agent_bom.demo_estate.showcase_graph import build_showcase_snapshot
from agent_bom.graph.attack_path_queue_rank import path_ranking_factors
from agent_bom.graph.container import UnifiedGraph


@lru_cache(maxsize=1)
def _graph() -> UnifiedGraph:
    return build_showcase_snapshot()


def _context(graph: UnifiedGraph, node_id: str) -> dict:
    node = graph.nodes.get(node_id)
    return (node.attributes.get("risk_context") or {}) if node is not None else {}


def test_demo_has_an_exposed_entry_path_to_a_crown_jewel() -> None:
    graph = _graph()
    nodes = {node.id: node for node in graph.nodes.values()}
    leader_paths = [
        path
        for path in graph.attack_paths
        if len(path.hops) >= 3
        and _context(graph, path.hops[0]).get("internet_exposed") is True
        and path_ranking_factors(path, nodes)["exposed_hop_ids"][:1] == [path.hops[0]]
        and _context(graph, path.hops[-1]).get("crown_jewel") is True
    ]
    assert leader_paths, "the demo must show exposure -> asset -> crown jewel"
    path = leader_paths[0]
    entry = _context(graph, path.hops[0])
    jewel = _context(graph, path.hops[-1])
    assert entry["internet_exposed"] is True
    assert any(reason["field"] == "internet_exposed" for reason in entry["reasons"])
    assert [reason["rule"] for reason in jewel["reasons"] if reason["field"] == "crown_jewel"] == ["sensitive_data_store"]
    assert jewel["scan_id"] == graph.scan_id


def test_demo_markers_are_sample_data_with_reasons() -> None:
    graph = _graph()
    contexts = [(node, node.attributes["risk_context"]) for node in graph.nodes.values() if node.attributes.get("risk_context")]
    assert any(context["is_admin"] is True for _, context in contexts)
    assert any(context["crown_jewel"] is True for _, context in contexts)
    for node, context in contexts:
        assert context["reasons"], node.id
        if context["crown_jewel"]:
            assert any(reason["field"] == "crown_jewel" for reason in context["reasons"])
    classified = [node for node, context in contexts if context["data_sensitivity"] == "phi"]
    assert classified
    assert all(node.attributes.get("synthetic") is True for node in classified)
