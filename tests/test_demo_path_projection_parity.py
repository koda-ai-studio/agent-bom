"""Demo path projection uses the persisted production evidence contract."""

from copy import deepcopy

import pytest

from agent_bom.demo_estate import showcase_graph
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.edge_freshness import stamp_edge_freshness
from agent_bom.graph.snapshot_paths import materialize_snapshot_paths


def graph_with_occurrences(exclusion):
    graph = UnifiedGraph(scan_id="demo-parity", tenant_id="tenant-a", created_at="2026-10-21T12:00:00Z")
    for node_id, kind in (
        ("agent:a", EntityType.AGENT),
        ("server:one", EntityType.SERVER),
        ("server:two", EntityType.SERVER),
        ("vuln:CVE-1", EntityType.VULNERABILITY),
    ):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id, severity="high", risk_score=8))
    for index, server in enumerate(("server:one", "server:two")):
        applicability = {"verdict": "likely", "basis": ["recorded_dependency"]}
        if index == 0 and exclusion == "unreachable":
            applicability["verdict"] = "unlikely"
        elif index == 0 and exclusion == "vex":
            applicability.update(vex_status="not_affected", vex_source="vendor")
        for source, target, relationship, evidence in (
            ("agent:a", server, RelationshipType.USES, {}),
            (server, "vuln:CVE-1", RelationshipType.VULNERABLE_TO, {"applicability": applicability}),
        ):
            graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, evidence=evidence))
        graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target="vuln:CVE-1",
                hops=["agent:a", server, "vuln:CVE-1"],
                edges=["uses", "vulnerable_to"],
                composite_risk=90 - index,
                summary=f"Recorded chain through {server}",
            )
        )
    return graph


@pytest.mark.parametrize("exclusion", [None, "unreachable", "vex"])
def test_demo_paths_match_production_for_shared_advisory_occurrences(exclusion):
    graph = graph_with_occurrences(exclusion)
    expected = deepcopy(graph)
    showcase_graph._record_showcase_attack_path_analysis(expected, count_paths=False)
    stamp_edge_freshness(expected)
    paths = [row.path.to_dict() for row in materialize_snapshot_paths(expected)]
    assert paths
    assert any("server:two" in path["hops"] for path in paths)
    if exclusion:
        assert not any("server:one" in path["hops"] for path in paths)

    assert showcase_graph._materialize_showcase_attack_paths(graph)
    assert [path.to_dict() for path in graph.attack_paths] == paths


@pytest.mark.parametrize("phase", ["freshness", "derivation"])
def test_failed_demo_path_projection_preserves_recorded_paths(monkeypatch, phase):
    graph = graph_with_occurrences(None)
    original = [path.to_dict() for path in graph.attack_paths]

    def fail(projected):
        if phase == "derivation":
            projected.attack_paths[0].summary = "partial projection"
            projected.attack_paths.clear()
        raise RuntimeError("fixture failure")

    target = (
        "agent_bom.graph.edge_freshness.stamp_edge_freshness"
        if phase == "freshness"
        else "agent_bom.graph.snapshot_paths.derived_attack_paths_with_kinds"
    )
    monkeypatch.setattr(target, fail)
    assert not showcase_graph._materialize_showcase_attack_paths(graph)
    assert [path.to_dict() for path in graph.attack_paths] == original
    assert "attack_path_fusion" not in graph.analysis_status
