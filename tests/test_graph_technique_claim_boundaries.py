"""Catalog validity alone does not substantiate an ATT&CK/ATLAS mapping."""

import pytest

from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.attack_path_mitre import derive_attack_path_techniques

pytestmark = pytest.mark.graph_contract("warn")


@pytest.mark.parametrize(
    "rel,target_type,source_attrs,evidence",
    [
        (RelationshipType.VULNERABLE_TO, EntityType.VULNERABILITY, {}, {}),
        (RelationshipType.VULNERABLE_TO, EntityType.VULNERABILITY, {"internet_exposed": True}, {}),
        (RelationshipType.STORES, EntityType.DATA_STORE, {}, {}),
        (RelationshipType.HAS_PERMISSION, EntityType.DATA_STORE, {}, {"access": "assume_chain"}),
        (RelationshipType.ACCESSED, EntityType.DATA_STORE, {}, {"event_id": "event:local"}),
        (RelationshipType.REACHES_TOOL, EntityType.TOOL, {}, {}),
        (RelationshipType.PROVIDES_TOOL, EntityType.TOOL, {}, {}),
        (RelationshipType.EXPOSES_CRED, EntityType.CREDENTIAL_REF, {}, {}),
        (RelationshipType.ASSUMES, EntityType.ROLE, {}, {}),
        (RelationshipType.EXPOSED_TO, EntityType.RESOURCE, {}, {}),
    ],
)
def test_generic_topology_is_not_a_technique_prerequisite(rel, target_type, source_attrs, evidence):
    graph = UnifiedGraph(scan_id="snapshot", tenant_id="tenant")
    graph.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a", attributes=source_attrs))
    graph.add_node(UnifiedNode(id="b", entity_type=target_type, label="b"))
    graph.add_edge(UnifiedEdge(source="a", target="b", relationship=rel, evidence=evidence, provenance={"basis": "observed"}))
    path = AttackPath(source="a", target="b", hops=["a", "b"], edges=[rel.value], reachability="confirmed")
    assert derive_attack_path_techniques(path, graph) == []


def test_native_cloud_authorization_read_is_modeled_not_observed_collection():
    from agent_bom.graph.builder import build_unified_graph_from_report
    from tests.test_graph_authorization_evidence_integration import _gcp_inventory

    graph = build_unified_graph_from_report({"scan_id": "native", "cloud_inventory": _gcp_inventory()})
    edge = next(
        e for e in graph.edges if e.relationship == RelationshipType.CAN_ACCESS and e.evidence.get("source") == "authorization-evidence"
    )
    path = AttackPath(source=edge.source, target=edge.target, hops=[edge.source, edge.target], edges=[edge.relationship.value])
    result = derive_attack_path_techniques(path, graph)
    assert [r.technique_id for r in result] == ["T1530"]
    assert result[0].evidence_basis == "modeled"
    assert result[0].confidence is None
    assert "current access unproven" in result[0].provenance
    # A parallel negative record cannot be discarded to retain the allow.
    graph.nodes[edge.source].attributes["authorization_boundaries"] = [{"target_node_id": edge.target, "decision": "explicit_deny"}]
    assert derive_attack_path_techniques(path, graph) == []


@pytest.mark.usefixtures("enable_experimental_traces")
def test_native_trace_tool_invocation_keeps_trace_receipt_and_attempt_semantics():
    from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore
    from agent_bom.graph.hop_evidence import exposure_hop_evidence
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence
    from tests.test_trace_graph_evidence import _build, _import_langfuse

    store = InMemoryRuntimeEventStore()
    _import_langfuse(store, "tenant-a", "trace-proof")
    graph, _ = _build(store, "tenant-a")
    edge = next(e for e in graph.edges if e.relationship == RelationshipType.INVOKED and e.evidence.get("source") == "runtime-trace")
    path = AttackPath(source=edge.source, target=edge.target, hops=[edge.source, edge.target], edges=[edge.relationship.value])
    annotate_attack_path_evidence(path, graph)
    assert exposure_hop_evidence(path)[0]["runtime_references"] == [{"trace_id": "trace-proof"}]
    assert [m.technique_id for m in derive_attack_path_techniques(path, graph)] == ["AML.T0053"]
    edge.evidence.update(count=3, error_count=3)
    annotate_attack_path_evidence(path, graph)
    assert path.hop_evidence[0]["runtime_outcome"] == "failed"
    assert path.reachability == "unknown"
    assert derive_attack_path_techniques(path, graph) == []


@pytest.mark.parametrize(
    "invalid", [{}, {"technique_id": []}, {"technique_id": "T1530", "hop_index": "oops"}, {"technique_id": "T1530", "tactics": None}]
)
def test_legacy_malformed_mapping_does_not_hide_valid_sibling(invalid):
    from agent_bom.graph.technique_mapping import technique_mappings_from_json

    valid = {"technique_id": "T1530", "hop_index": 1, "evidence_basis": "modeled"}
    mappings = technique_mappings_from_json([invalid, valid])
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1530"


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), -0.1, 1.1, "unavailable", True])
def test_unqualified_mapping_confidence_stays_unavailable(confidence):
    import json

    from agent_bom.graph.technique_mapping import technique_mappings_from_json

    mappings = technique_mappings_from_json([{"technique_id": "T1530", "evidence_basis": "modeled", "confidence": confidence}])
    assert len(mappings) == 1
    assert mappings[0].confidence is None
    json.dumps(mappings[0].to_dict(), allow_nan=False)
