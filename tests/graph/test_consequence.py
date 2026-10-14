"""An authority path must carry its scope, blockers and occurrence evidence."""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode
from agent_bom.graph.consequence.contracts import ConsequenceRequest
from agent_bom.graph.consequence.service import assess_consequences
from tests.graph.test_compromise import AT, STAMP, graph, receipt

# Hand-built graphs here use placeholder relationship pairs to exercise graph
# mechanics; producers are held to the contract in test_graph_relationship_contract.
pytestmark = pytest.mark.graph_contract("warn")


def assess(g, **changes):
    request = ConsequenceRequest.model_validate(
        {
            "root_node_id": "principal:reader",
            "mode": "assumed_compromise",
            "assume_control": True,
            **changes,
        }
    )
    return assess_consequences(g, request, tenant_id="tenant:a", at=AT)


def bound_graph(*, actions=None):
    g = graph(receipt())
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="Agent"))
    g.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="principal:reader",
            relationship=RelationshipType.AUTHENTICATES_AS,
            first_seen=STAMP,
            evidence={
                "session_binding": {
                    "schema_version": "graph.session-binding.v1",
                    "source_node_id": "agent:a",
                    "identity_node_id": "principal:reader",
                    "principal_id": "reader",
                    "provider": "gcp",
                    "tenant_id": "tenant:a",
                    "scan_id": g.scan_id,
                    "session_id": "session:a",
                    "state": "active",
                    "observed_at": STAMP,
                    "expires_at": "2026-10-09T12:30:00+00:00",
                    "evidence_ref": "collector:binding:a",
                    "scope": actions or [{"action": "storage.objects.get", "resource": "projects/p/buckets/b"}],
                }
            },
        )
    )
    return g


def test_direct_read_and_multihop_binding_preserve_action_and_evidence():
    g = bound_graph()
    before = deepcopy(g.to_dict())
    result = assess(g, root_node_id="agent:a")
    assert result.schema_version == "graph.consequence.v1"
    assert len(result.consequences) == 1
    item = result.consequences[0]
    assert item.status == "supported"
    assert item.category == "read_data" and item.action == "storage.objects.get"
    assert item.node_ids == ["agent:a", "principal:reader", "data:b"]
    assert item.edge_ids == [g.edges[1].id, g.edges[0].id]
    assert item.session_ids == ["session:a"]
    assert item.binding_ids == ["binding:read"]
    assert result.counts.supported == 1 and result.counts.unknown == 0
    assert result.collection_coverage == "unknown" and result.observed_effects == "not_established"
    assert g.to_dict() == before
    assert result.model_dump() == assess(g, root_node_id="agent:a").model_dump()


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("state", "revoked", "session_revoked"),
        ("expires_at", STAMP, "session_expired"),
        ("principal_id", "different", "identity_scope_mismatch"),
        ("tenant_id", "tenant:b", "identity_scope_mismatch"),
        ("observed_at", "2026-10-01T00:00:00Z", "identity_evidence_stale"),
    ],
)
def test_invalid_identity_stops_positive_propagation(field, value, reason):
    g = bound_graph()
    g.edges[1].evidence["session_binding"][field] = value
    result = assess(g, root_node_id="agent:a")
    assert not result.consequences
    assert reason in result.frontier[0].reason_codes
    assert result.counts.supported == 0


def test_registered_identity_and_shared_credentials_never_create_a_session():
    g = bound_graph()
    g.edges[1].evidence = {"identity_match_basis": "exact_node_id", "mapping_method": "explicit_identity_binding"}
    result = assess(g, root_node_id="agent:a")
    assert not result.consequences
    assert "identity_session_not_recorded" in result.frontier[0].reason_codes


def test_deny_and_stale_permission_remain_visible():
    g = graph(receipt(decision="explicit_deny"), receipt(action="storage.objects.create", observed_at="2026-10-01T00:00:00Z"))
    result = assess(g)
    assert {item.status for item in result.consequences} == {"blocked", "unknown"}
    assert result.counts.blocked == 1 and result.counts.unknown == 1


def test_read_permission_never_transfers_control_to_target():
    g = bound_graph()
    g.add_node(UnifiedNode(id="data:other", entity_type=EntityType.DATA_STORE, label="Other"))
    g.add_edge(UnifiedEdge(source="data:b", target="data:other", relationship=RelationshipType.HAS_PERMISSION))
    result = assess(g, root_node_id="agent:a")
    assert all(item.target_node_id != "data:other" for item in result.consequences)


def test_session_action_scope_is_not_dropped():
    g = bound_graph(actions=[{"action": "storage.objects.create", "resource": "projects/p/buckets/b"}])
    result = assess(g, root_node_id="agent:a")
    assert result.consequences[0].status == "blocked"
    assert "outside_session_scope" in result.consequences[0].reason_codes


def test_finding_without_prerequisites_never_grants_component_control():
    g = bound_graph()
    g.add_node(UnifiedNode(id="finding:v", entity_type=EntityType.VULNERABILITY, label="CVE-example"))
    g.add_edge(UnifiedEdge(source="finding:v", target="agent:a", relationship=RelationshipType.AFFECTS))
    result = assess(g, root_node_id="finding:v", mode="vulnerability", assume_control=False, affected_node_id="agent:a")
    assert result.prerequisites.status == "unknown"
    assert "local_exploitability_not_collected" in result.prerequisites.reason_codes
    assert not result.consequences
    assert result.affected_node_id == "agent:a"


@pytest.mark.parametrize("changes", [{"assume_control": 1}, {"assume_control": False}, {"max_states": 0}, {"extra": 1}])
def test_strict_assumptions_and_bounds(changes):
    with pytest.raises(ValidationError):
        assess(graph(receipt()), **changes)


def test_partial_graph_never_promotes_allows_and_counts_are_lower_bounds():
    g = bound_graph()
    g.completeness.truncated = True
    result = assess(g, root_node_id="agent:a")
    assert result.truncated and result.counts.lower_bound
    assert result.counts.supported == 0


def test_different_sessions_to_same_identity_are_not_deduplicated():
    g = bound_graph()
    # Two paths with different restrictions, both ending at the same principal.
    g.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="Delegate"))
    first = deepcopy(g.edges[1].evidence["session_binding"])
    first.update(identity_node_id="agent:b", principal_id="delegate", session_id="session:delegate")
    g.nodes["agent:b"].attributes.update(principal_id="delegate", cloud_provider="gcp")
    g.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="agent:b",
            relationship=RelationshipType.DELEGATED_TO,
            first_seen=STAMP,
            evidence={"session_binding": first},
        )
    )
    second = deepcopy(g.edges[1].evidence["session_binding"])
    second.update(source_node_id="agent:b", session_id="session:second")
    g.add_edge(
        UnifiedEdge(
            source="agent:b",
            target="principal:reader",
            relationship=RelationshipType.AUTHENTICATES_AS,
            first_seen=STAMP,
            evidence={"session_binding": second},
        )
    )
    result = assess(g, root_node_id="agent:a")
    assert len(result.consequences) == 2
    assert {tuple(item.session_ids) for item in result.consequences} == {("session:a",), ("session:delegate", "session:second")}
    assert result.counts.supported == 1  # unique action/target consequences, separate witnesses


def test_sqlite_restart_preserves_path_semantics(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    g = bound_graph()
    store = SQLiteGraphStore(tmp_path / "consequence.db")
    store.save_graph(g)
    restored = SQLiteGraphStore(tmp_path / "consequence.db").load_graph(scan_id=g.scan_id, tenant_id=g.tenant_id)
    assert assess(restored, root_node_id="agent:a").model_dump() == assess(g, root_node_id="agent:a").model_dump()


def test_collector_projection_explicitly_marks_local_exploitability_unavailable():
    from agent_bom.graph.builder import build_unified_graph_from_report

    g = build_unified_graph_from_report(
        {
            "scan_id": "exploitability-gap",
            "agents": [
                {
                    "name": "fixture",
                    "mcp_servers": [
                        {
                            "name": "server",
                            "packages": [
                                {
                                    "name": "example",
                                    "version": "1.0",
                                    "ecosystem": "pypi",
                                    "vulnerabilities": [
                                        {
                                            "id": "CVE-example",
                                            "severity": "high",
                                            "network_exploitable": True,
                                            "is_kev": True,
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )
    finding = next(n for n in g.nodes.values() if n.entity_type == EntityType.VULNERABILITY)
    evidence = finding.attributes["exploitability_assessment"]
    assert evidence["status"] == "unavailable"
    assert evidence["verdict"] is None
    assert "local_exploitability_not_collected" in evidence["reason_codes"]


def test_deny_on_parallel_permission_relationship_prevents_positive_same_request_claim():
    g = graph(receipt())
    g.add_edge(
        UnifiedEdge(
            source="principal:reader",
            target="data:b",
            relationship=RelationshipType.HAS_PERMISSION,
            first_seen=STAMP,
            evidence={"freshness": "fresh", "authorization_decisions": [receipt(decision="explicit_deny")]},
        )
    )
    result = assess(g)
    assert result.counts.supported == 0
    assert all(item.status == "blocked" for item in result.consequences)


def test_mismatched_provider_in_a_later_session_cannot_rebind_an_existing_scope():
    g = bound_graph()
    g.edges[1].evidence["session_binding"]["provider"] = "azure"
    result = assess(g, root_node_id="agent:a")
    assert not result.consequences


def test_limits_and_unknown_action_names_do_not_invent_safe_or_write_access():
    g = bound_graph()
    g.edges[0].evidence["authorization_decisions"][0]["action"] = "create_pull_request"
    result = assess(g, root_node_id="agent:a", max_states=1)
    assert result.truncated and result.counts.lower_bound
    direct = assess(g)
    assert direct.consequences[0].category == "unclassified"
    assert not any(item.category in {"merge", "alter_deployment"} for item in direct.consequences)
