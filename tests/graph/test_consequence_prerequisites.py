"""Prerequisites retain collected advisory facts without inventing exploitation."""

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.consequence.contracts import ConsequenceRequest
from agent_bom.graph.consequence.service import assess_consequences
from tests.graph.test_compromise import AT


def test_inventory_match_and_advisory_conditions_are_collected_separately_from_local_proof():
    graph = UnifiedGraph(scan_id="scope:a", tenant_id="tenant:a")
    graph.add_node(
        UnifiedNode(
            id="vuln:x",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-fixture",
            attributes={
                "attack_vector": "NETWORK",
                "privileges_required": "HIGH",
                "user_interaction": "REQUIRED",
                "is_kev": True,
            },
        )
    )
    graph.add_node(UnifiedNode(id="pkg:a", entity_type=EntityType.PACKAGE, label="example@1.0"))
    edge = UnifiedEdge(
        source="pkg:a",
        target="vuln:x",
        relationship=RelationshipType.VULNERABLE_TO,
        evidence={"package_version": "1.0", "source": "inventory"},
    )
    graph.add_edge(edge)
    request = ConsequenceRequest(root_node_id="vuln:x", affected_node_id="pkg:a", mode="vulnerability")
    result = assess_consequences(graph, request, tenant_id="tenant:a", at=AT)
    checks = {item.name: item for item in result.prerequisites.checks}
    assert checks["affected_inventory"].status == "recorded"
    assert checks["affected_inventory"].evidence_refs == [edge.id]
    assert checks["required_privileges"].value == "HIGH"
    assert checks["required_privileges"].basis == "advisory"
    assert checks["deployed_configuration"].status == "missing"
    assert checks["local_exploitation"].status == "missing"
    assert result.prerequisites.status == "unknown" and not result.consequences


def test_another_occurrences_receipt_cannot_satisfy_selected_package():
    from tests.graph.test_consequence import bound_graph

    graph = bound_graph()
    graph.add_node(UnifiedNode(id="vuln:x", entity_type=EntityType.VULNERABILITY, label="CVE-fixture"))
    for suffix in ("a", "b"):
        graph.add_node(UnifiedNode(id=f"pkg:{suffix}", entity_type=EntityType.PACKAGE, label="same-name"))
        graph.add_edge(
            UnifiedEdge(
                source=f"pkg:{suffix}",
                target="vuln:x",
                relationship=RelationshipType.VULNERABLE_TO,
                evidence={"package_version": "9" if suffix == "a" else "1"},
            )
        )
    result = assess_consequences(
        graph, ConsequenceRequest(root_node_id="vuln:x", affected_node_id="pkg:b", mode="vulnerability"), tenant_id="tenant:a", at=AT
    )
    checks = {item.name: item for item in result.prerequisites.checks}
    assert checks["recorded_version"].value == "1"
    assert result.counts.supported == 0


def test_advisory_projection_is_partial_and_never_exploitable():
    from agent_bom.graph.exploitability_projection import project_exploitability

    result = project_exploitability({"attack_vector": "NETWORK", "is_kev": True}, "vuln:x")
    assert result["status"] == "partial" and result["verdict"] == "unknown"
    assert result["evidence_refs"] == ["vuln:x"]
    assert "local_exploitability_not_collected" in result["reason_codes"]
