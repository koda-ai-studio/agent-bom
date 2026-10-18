"""Explicit credential references join native inventory without inventing authority."""

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def test_binding_projection_does_not_materialize_unrelated_inventory(monkeypatch):
    from agent_bom.graph.credential_bindings import project_credential_bindings

    class StreamingNodes:
        def __iter__(self):
            pytest.fail("must not copy the complete node mapping")

        def values(self):
            yield UnifiedNode(
                id="native-0", entity_type=EntityType.SERVICE_PRINCIPAL, label="native", attributes={"canonical_id": "native-id"}
            )

        def get(self, key, default=None):
            assert key in {"native-id", "cred:server:CLOUD_TOKEN"}
            return default

    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant-a")
    graph.nodes = StreamingNodes()
    monkeypatch.setattr("agent_bom.graph.credential_bindings.mcp_server_graph_id_for", lambda *args: "server")
    project_credential_bindings(graph, report()["agents"], "fixture")


def report(reference="native-id", provider="azure"):
    return {
        "agents": [
            {
                "name": "worker",
                "source_id": "device-a",
                "mcp_servers": [
                    {
                        "name": "cloud",
                        "credential_env_vars": ["CLOUD_TOKEN"],
                        "identity_bindings": [
                            {
                                "credential_ref": "CLOUD_TOKEN",
                                "identity_canonical_id": reference,
                                "provider": provider,
                                "evidence_source": "mcp-config",
                            }
                        ],
                    }
                ],
            }
        ],
    }


def inventory(*, count=1, provider="azure", kind=EntityType.SERVICE_PRINCIPAL):
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant-a")
    for i in range(count):
        graph.add_node(
            UnifiedNode(
                id=f"native-{i}", entity_type=kind, label="same-name", attributes={"canonical_id": "native-id", "cloud_provider": provider}
            )
        )
    return graph


@pytest.mark.parametrize("kind", [EntityType.SERVICE_PRINCIPAL, EntityType.SERVICE_ACCOUNT, EntityType.MANAGED_IDENTITY, EntityType.ROLE])
def test_exact_canonical_binding_reuses_native_inventory(kind):
    graph = build_unified_graph_from_report(report(), container=inventory(kind=kind), tenant_id="tenant-a")
    edges = [e for e in graph.edges if e.relationship is RelationshipType.AUTHENTICATES_AS]
    assert len(edges) == 1 and edges[0].target == "native-0"
    assert graph.nodes["native-0"].entity_type is kind
    assert edges[0].evidence["identity_match_basis"] == "exact_canonical_id"
    assert edges[0].evidence["execution_proven"] is False
    assert graph.get_node("native-id") is None


def test_ambiguous_canonical_binding_preserves_candidates_without_joining():
    graph = build_unified_graph_from_report(report(), container=inventory(count=2), tenant_id="tenant-a")
    auth = [e for e in graph.edges if e.relationship is RelationshipType.AUTHENTICATES_AS]
    assert all(e.target not in {"native-0", "native-1"} for e in auth)
    candidates = [e for e in graph.edges if e.relationship is RelationshipType.POSSIBLY_CORRELATES_WITH]
    assert {e.target for e in candidates} == {"native-0", "native-1"}
    assert all(e.evidence["execution_proven"] is False for e in candidates)


def test_repeated_ambiguous_binding_cannot_promote_an_earlier_placeholder():
    payload = report()
    server = payload["agents"][0]["mcp_servers"][0]
    server["credential_env_vars"].append("SECOND_TOKEN")
    server["identity_bindings"].append({**server["identity_bindings"][0], "credential_ref": "SECOND_TOKEN"})
    graph = build_unified_graph_from_report(payload, container=inventory(count=2), tenant_id="tenant-a")
    auth = [edge for edge in graph.edges if edge.relationship is RelationshipType.AUTHENTICATES_AS]
    assert len(auth) == 2
    assert all(edge.evidence["identity_match_basis"] == "ambiguous_canonical_id" for edge in auth)
    for edge in auth:
        assert {
            candidate.target
            for candidate in graph.edges
            if candidate.source == edge.target and candidate.relationship is RelationshipType.POSSIBLY_CORRELATES_WITH
        } == {"native-0", "native-1"}


@pytest.mark.parametrize("count", [1, 2])
def test_store_backed_binding_matches_memory_with_evicted_native_nodes(count):
    from agent_bom.graph.store_backed import open_store_backed_unified_graph

    payload = report()
    server = payload["agents"][0]["mcp_servers"][0]
    server["credential_env_vars"].append("SECOND_TOKEN")
    server["identity_bindings"].append({**server["identity_bindings"][0], "credential_ref": "SECOND_TOKEN"})
    memory = inventory(count=count)
    stored = open_store_backed_unified_graph(backend="sqlite", tenant_id="tenant-a", scan_id="scan", capacity=1)
    try:
        for node in memory.nodes.values():
            stored.add_node(node)
        for graph in (memory, stored):
            build_unified_graph_from_report(payload, container=graph, tenant_id="tenant-a")
        relationships = {RelationshipType.AUTHENTICATES_AS, RelationshipType.POSSIBLY_CORRELATES_WITH}

        def bindings(graph):
            return sorted(
                (edge.source, edge.target, edge.relationship.value, edge.evidence["identity_match_basis"])
                for edge in graph.edges
                if edge.relationship in relationships
            )

        assert bindings(stored) == bindings(memory)
        assert len(bindings(stored)) == (2 if count == 1 else 6)
    finally:
        stored.close()


@pytest.mark.parametrize("reference,provider", [("same-name", "azure"), ("native-id", "gcp")])
def test_names_and_provider_conflicts_never_bind(reference, provider):
    graph = build_unified_graph_from_report(report(reference, provider), container=inventory(), tenant_id="tenant-a")
    assert not any(e.target == "native-0" and e.relationship is RelationshipType.AUTHENTICATES_AS for e in graph.edges)


def test_existing_non_identity_id_is_not_overwritten_or_authenticated():
    graph = inventory(kind=EntityType.DATA_STORE)
    graph = build_unified_graph_from_report(report("native-0"), container=graph, tenant_id="tenant-a")
    assert graph.nodes["native-0"].entity_type is EntityType.DATA_STORE
    assert not any(e.target == "native-0" and e.relationship is RelationshipType.AUTHENTICATES_AS for e in graph.edges)


def test_exact_id_does_not_fall_back_to_shadowing_canonical_alias():
    graph = inventory(count=2)
    graph.nodes["native-1"].attributes["canonical_id"] = "native-0"
    graph = build_unified_graph_from_report(report("native-0"), container=graph, tenant_id="tenant-a")
    assert {e.target for e in graph.edges if e.relationship is RelationshipType.AUTHENTICATES_AS} == {"native-0"}


def test_native_cloud_role_projects_before_credential_binding():
    arn = "arn:aws:iam::123456789012:role/worker"
    payload = report(f"role:aws:{arn}", "aws")
    payload["cloud_inventory"] = {
        "provider": "aws",
        "status": "ok",
        "account_id": "123456789012",
        "roles": [{"name": "worker", "arn": arn, "principal_type": "role"}],
    }
    graph = build_unified_graph_from_report(payload, tenant_id="tenant-a")
    edges = [edge for edge in graph.edges if edge.relationship is RelationshipType.AUTHENTICATES_AS]
    assert len(edges) == 1
    target = graph.nodes[edges[0].target]
    assert target.entity_type is EntityType.ROLE
    assert target.attributes["principal_resource_id"] == arn
    assert edges[0].evidence["identity_match_basis"] == "exact_node_id"
    assert edges[0].evidence["tier"] == "modeled_infrastructure"
    # The configured chain exists without promoting it to runtime execution.
    credential = graph.nodes[edges[0].source]
    server = credential.attributes["server"]
    assert any(edge.source == server and edge.target == credential.id for edge in graph.edges)
    assert any(edge.target == server and edge.relationship is RelationshipType.USES for edge in graph.edges)
