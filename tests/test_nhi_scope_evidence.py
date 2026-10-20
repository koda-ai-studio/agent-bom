"""Discovered OAuth scope metadata is not an authorization receipt for a tool."""

from dataclasses import replace

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.nhi_overlay import apply_nhi_overlay, apply_nhi_overlay_from_report
from agent_bom.identity.okta_nhi import DiscoveredNonHumanIdentity


def _identity(provider="okta", source_scope="https://one.okta.invalid"):
    return DiscoveredNonHumanIdentity(
        identity_id="app-1",
        name="inventory-reader",
        identity_type="service_account",
        provider=provider,
        source_scope=source_scope,
        scopes=("read_file",),
    )


def _graph(scan_id="scan-1", tenant="tenant-1"):
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant)
    for provider in ("okta", "unrelated-platform"):
        graph.add_node(
            UnifiedNode(
                id=f"tool:{provider}:reader",
                entity_type=EntityType.TOOL,
                label="read_file",
                attributes={"provider": provider, "account_id": "unrelated-account"},
            )
        )
    return graph


@pytest.mark.parametrize("provider", ["okta", "entra"])
@pytest.mark.parametrize("scope", ["read_file", " READ_FILE ", "*", "tool:okta:reader"])
def test_scope_metadata_cannot_assert_tool_access(provider, scope):
    graph = _graph()
    identity = replace(_identity(provider), scopes=(scope,))
    apply_nhi_overlay(graph, [identity])

    assert not [edge for edge in graph.edges if edge.relationship == RelationshipType.SCOPED_TO]
    [node] = [node for node in graph.nodes.values() if node.entity_type == EntityType.MANAGED_IDENTITY]
    assert node.attributes["scopes"] == [scope]
    # Even an exact tool ID string is not a grant binding principal + target.
    assert node.attributes["source_scope"] == identity.source_scope


def test_report_projection_preserves_org_scoped_identity_and_membership():
    graph = _graph()
    identities = [_identity(source_scope=f"https://{org}.okta.invalid") for org in ("one", "two")]
    report = {"identity_discovery": {"identities": [identity.to_dict() for identity in identities]}}
    first = apply_nhi_overlay_from_report(graph, report)
    second = apply_nhi_overlay_from_report(graph, report)

    assert first == {"nodes_added": 4, "edges_added": 2}
    assert second == {"nodes_added": 0, "edges_added": 0}
    nodes = [node for node in graph.nodes.values() if node.entity_type == EntityType.MANAGED_IDENTITY]
    assert len(nodes) == 2
    for edge in graph.edges:
        assert edge.relationship == RelationshipType.MEMBER_OF
        assert graph.nodes[edge.source].attributes["source_scope"] == graph.nodes[edge.target].attributes["org_url"]
        assert edge.evidence["basis"] == "org_api_collection"


def test_overlay_does_not_remove_independently_evidenced_permissions():
    graph = _graph()
    graph.add_node(UnifiedNode(id="managed_identity:issuer:principal", entity_type=EntityType.MANAGED_IDENTITY, label="issuer-principal"))
    edge = UnifiedEdge(
        source="managed_identity:issuer:principal",
        target="tool:okta:reader",
        relationship=RelationshipType.SCOPED_TO,
        evidence={"source": "explicit-grant-fixture", "principal_id": "issuer:principal", "target_id": "tool:okta:reader"},
    )
    graph.add_edge(edge)
    before = edge.to_dict()
    apply_nhi_overlay(graph, [_identity()])
    assert [item.to_dict() for item in graph.edges if item.relationship == RelationshipType.SCOPED_TO] == [before]


def test_scope_updates_revocation_and_deletion_survive_snapshot_roundtrip(tmp_path):
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph

    original = _identity()
    snapshots = [
        [original],
        [replace(original, scopes=("write_file",))],
        [replace(original, scopes=())],
        [],
        [original],
    ]
    ids = []
    with open_graph_db(tmp_path / "nhi.db") as db:
        for index, identities in enumerate(snapshots):
            graph = _graph(scan_id=f"scan-{index}")
            apply_nhi_overlay(graph, identities)
            save_graph(db, graph)
            restored = load_graph(db, tenant_id="tenant-1", scan_id=graph.scan_id)
            nodes = [node for node in restored.nodes.values() if node.entity_type == EntityType.MANAGED_IDENTITY]
            ids.append([node.id for node in nodes])
            assert not [edge for edge in restored.edges if edge.relationship == RelationshipType.SCOPED_TO]
            assert [node.attributes["scopes"] for node in nodes] == [list(identity.scopes) for identity in identities]
            assert not load_graph(db, tenant_id="other-tenant", scan_id=graph.scan_id).nodes
        assert ids[0] == ids[1] == ids[2] == ids[4]
        assert ids[3] == []
        # Historical observations remain unchanged when current scopes disappear.
        prior = load_graph(db, tenant_id="tenant-1", scan_id="scan-0")
        [node] = [node for node in prior.nodes.values() if node.entity_type == EntityType.MANAGED_IDENTITY]
        assert node.attributes["scopes"] == ["read_file"]
