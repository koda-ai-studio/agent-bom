"""A path must identify a directed relationship before borrowing its evidence."""

from dataclasses import replace

import pytest

from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.hop_evidence import exposure_hop_evidence
from agent_bom.graph.path_evidence import annotate_attack_path_evidence


def graph_and_path():
    graph = UnifiedGraph(scan_id="snapshot", tenant_id="tenant")
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    graph.add_node(UnifiedNode(id="resource:b", entity_type=EntityType.RESOURCE, label="b"))
    graph.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="resource:b",
            relationship=RelationshipType.ACCESSED,
            evidence={"freshness": "fresh", "event_id": "event:1"},
            provenance={"source": "runtime"},
        )
    )
    return graph, AttackPath(source="agent:a", target="resource:b", hops=["agent:a", "resource:b"], edges=["accessed"])


@pytest.mark.parametrize("parallel", [False, True])
def test_missing_relationship_cannot_borrow_any_runtime_receipt(parallel):
    graph, path = graph_and_path()
    if parallel:
        graph.add_edge(
            UnifiedEdge(
                source=path.source,
                target=path.target,
                relationship=RelationshipType.CAN_ACCESS,
                evidence={"freshness": "fresh"},
                provenance={"source": "policy"},
                confidence=1,
            )
        )
    path.edges = []
    annotate_attack_path_evidence(path, graph)
    assert path.reachability == "unknown"
    receipt = exposure_hop_evidence(path)[0]
    assert not receipt["complete"]
    assert receipt["reason_codes"] == ["hop_relationship_missing"]
    assert receipt["runtime_references"] == []


def test_conflicting_duplicate_typed_hop_does_not_choose_highest_confidence():
    graph, path = graph_and_path()
    original = graph.edges[0]
    # Imported adjacency/index can contain conflicting records for the same key.
    candidates = [original, replace(original, confidence=0.1, evidence={"blocked": True})]
    annotate_attack_path_evidence(path, graph, hop_edges={(path.source, path.target): candidates})
    assert path.reachability == "unknown"
    assert path.hop_evidence[0]["reason_codes"] == ["ambiguous_hop_relationship"]


def test_typed_receipt_preserves_exact_edge_identity():
    graph, path = graph_and_path()
    annotate_attack_path_evidence(path, graph)
    receipt = exposure_hop_evidence(path)[0]
    assert receipt["canonical_edge_id"] == graph.edges[0].canonical_id
    assert receipt["runtime_references"] == [{"event_id": "event:1"}]


def test_failed_trace_aggregate_is_not_a_successful_path():
    graph, path = graph_and_path()
    graph.edges[0].evidence.update(source="runtime-trace", count=3, error_count=3)
    annotate_attack_path_evidence(path, graph)
    assert path.reachability == "unknown"
    assert path.hop_evidence[0]["runtime_outcome"] == "failed"


@pytest.mark.parametrize("reverse", [False, True])
def test_merged_conflicting_runtime_records_keep_negative_evidence(reverse):
    graph, path = graph_and_path()
    original = graph.edges[0]
    original.evidence.update(blocked=False, decision="allowed")
    denied = replace(original, evidence={**original.evidence, "event_id": "event:2", "blocked": True, "decision": "denied"})
    if reverse:
        graph = UnifiedGraph.from_dict({**graph.to_dict(), "edges": []})
        graph.add_edge(denied)
        graph.add_edge(original)
    else:
        graph.add_edge(denied)
    annotate_attack_path_evidence(path, graph)
    assert path.reachability == "unknown"
    assert path.hop_evidence[0]["runtime_observed_state"] == "blocked"
    assert {r["event_id"] for r in exposure_hop_evidence(path)[0]["runtime_references"]} == {"event:1", "event:2"}


def test_unknown_relationship_name_cannot_confirm_a_typed_path():
    graph, path = graph_and_path()
    path.edges = ["invented"]
    candidate = replace(graph.edges[0], relationship="invented")
    annotate_attack_path_evidence(path, graph, hop_edges={(path.source, path.target): [candidate]})
    assert path.reachability == "unknown"
    assert path.hop_evidence[0]["reason_codes"] == ["unsupported_hop_relationship"]


@pytest.mark.parametrize("rows", [None, [], ["invalid"], [{"event_id": "event:2"}, None], [{"event_id": f"event:{i}"} for i in range(17)]])
def test_incomplete_runtime_receipts_cannot_confirm_path(rows):
    graph, path = graph_and_path()
    graph.edges[0].evidence["runtime_receipts"] = rows
    annotate_attack_path_evidence(path, graph)
    assert path.reachability == "unknown"
    assert not path.hop_evidence[0]["complete"]
    assert "runtime_receipts_limited" in path.hop_evidence[0]["reason_codes"]
    references = exposure_hop_evidence(path)[0]["runtime_references"]
    if not rows or rows == ["invalid"]:
        assert {"event_id": "event:1"} not in references


def test_merged_runtime_receipts_reopen_with_exact_identity_and_conflicting_evidence(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from tests.test_exposure_path_evidence_parity import _serialize_both

    graph, path = graph_and_path()
    original = graph.edges[0]
    graph.add_edge(replace(original, evidence={"event_id": "event:2", "trace_id": "trace:2", "blocked": True}))
    graph.attack_paths = [annotate_attack_path_evidence(path, graph)]
    database = tmp_path / "receipts.db"
    SQLiteGraphStore(database).save_graph(graph)
    reopened = SQLiteGraphStore(database).load_graph(tenant_id="tenant", scan_id="snapshot")
    assert reopened is not None
    for payload in _serialize_both(reopened.attack_paths[0], nodes=list(reopened.nodes.values()), edges=reopened.edges):
        hop = payload["hopEvidence"][0]
        assert hop["canonical_edge_id"] == original.canonical_id
        assert hop["runtime_outcome"] == "blocked"
        assert sorted(hop["runtime_references"], key=lambda item: item["event_id"]) == [
            {"event_id": "event:1"},
            {"event_id": "event:2", "trace_id": "trace:2"},
        ]
        assert payload["reachability"] == "unknown"
