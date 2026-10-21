"""Account scope is evidence, not a display label or a collector's identity."""

import pytest

from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.graph.asset_canonicalize import canonicalize_assets
from agent_bom.graph.asset_identity import strong_keys
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import correlation_identity
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

CASES = [
    ("aws", "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", "123456789012", "987654321098"),
    ("azure", "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm", "sub-a", "sub-b"),
    ("gcp", "projects/project-a/zones/us-central1-a/instances/vm", "project-a", "project-b"),
]


def resource(provider, native, account, node_id="asset"):
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.CLOUD_RESOURCE,
        label="instance",
        attributes={"cloud_provider": provider, "resource_id": native, "account_id": account},
    )


@pytest.mark.parametrize("provider,native,owner,other", CASES)
def test_conflicting_native_owner_never_supplies_strong_merge_keys(provider, native, owner, other):
    node = resource(provider, native, other)
    assert not strong_keys(node)
    assert correlation_identity(node, scan_id="one") != correlation_identity(node, scan_id="two")


@pytest.mark.parametrize("provider,native,owner,other", CASES)
def test_conflicting_envelope_cannot_collapse_nodes_before_canonicalization(provider, native, owner, other):
    assert cloud_resource_node_id(provider, "instance", {"id": native}, owner, "") != cloud_resource_node_id(
        provider, "instance", {"id": native}, other, ""
    )


@pytest.mark.parametrize("provider,native,owner,other", CASES)
def test_canonicalization_preserves_conflicting_observation_and_reports_gap(provider, native, owner, other):
    graph = UnifiedGraph()
    graph.add_node(resource(provider, native, owner, "valid"))
    graph.add_node(resource(provider, native, other, "conflicted"))
    canonicalize_assets(graph)
    assert len(graph.nodes) == 2
    assert graph.nodes["conflicted"].attributes["identity_scope"]["status"] == "conflict"
    assert "conflicting_cloud_scope" in graph.analysis_status["asset_canonicalization"].reason_codes


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_accountless_local_resource_is_snapshot_scoped(provider):
    node = resource(provider, "local-resource-1", "")
    assert correlation_identity(node, scan_id="one") != correlation_identity(node, scan_id="two")


@pytest.mark.parametrize("provider,native,owner,other", CASES)
def test_qualified_native_id_can_supply_owner_without_collector_account(provider, native, owner, other):
    assert strong_keys(resource(provider, native, "")) == strong_keys(resource(provider, native, owner))


def test_global_s3_identifier_does_not_require_invented_account():
    node = resource("aws", "arn:aws:s3:::globally-named-bucket", "")
    assert strong_keys(node)
    assert correlation_identity(node, scan_id="one") == correlation_identity(node, scan_id="two")


def test_conflicting_account_aliases_cannot_be_hidden_by_first_nonempty_field():
    node = resource("aws", "i-0123456789abcdef0", "123456789012")
    node.attributes.update(cloud_account_id="987654321098", region="us-east-1")
    assert not strong_keys(node)


def test_azure_normalized_resource_keeps_scope_conflict_explicit():
    from agent_bom.cloud.resource_model import normalize_cloud_inventory

    native = CASES[1][1].replace("Microsoft.Compute/virtualMachines/vm", "Microsoft.KeyVault/vaults/demo")
    rows = normalize_cloud_inventory({"provider": "azure", "subscription_id": "sub-b", "key_vaults": [{"id": native, "name": "demo"}]})
    assert len(rows) == 1
    assert rows[0].resource_id == native
    assert rows[0].to_dict()["identity_scope"]["status"] == "conflict"


@pytest.mark.parametrize("disk_backed", [False, True])
def test_conflicted_scope_never_remains_a_traversable_hop(disk_backed):
    from contextlib import nullcontext

    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.store_backed import open_store_backed_unified_graph
    from agent_bom.graph.types import RelationshipType

    context = open_store_backed_unified_graph(tenant_id="t", scan_id="s") if disk_backed else nullcontext(UnifiedGraph())
    with context as graph:
        graph.add_node(resource("aws", CASES[0][1], CASES[0][3]))
        graph.add_node(UnifiedNode(id="caller", entity_type=EntityType.ROLE, label="role"))
        graph.add_edge(UnifiedEdge(source="caller", target="asset", relationship=RelationshipType.CAN_ACCESS))
        canonicalize_assets(graph)
        edge = next(iter(graph.edges))
        assert edge.traversable is False
        assert edge.evidence["identity_scope_status"] == "conflict"


def test_azure_public_ip_frontend_is_a_binding_not_proven_ingress():
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.types import RelationshipType

    prefix = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/"
    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": {
                "provider": "azure",
                "account_id": "sub-a",
                "subscription_id": "sub-a",
                "status": "ok",
                "public_ips": [{"id": prefix + "publicIPAddresses/pip", "name": "pip", "ip_address": "192.0.2.2"}],
                "load_balancers": [{"id": prefix + "loadBalancers/lb", "name": "lb", "public_ip_ids": [prefix + "publicIPAddresses/pip"]}],
            }
        }
    )
    bindings = [edge for edge in graph.edges if edge.relationship == RelationshipType.EXPOSED_TO]
    assert bindings
    assert all(not edge.traversable and edge.evidence["network_reachability"] == "unknown" for edge in bindings)


def test_missing_provider_label_cannot_hide_native_account_conflict():
    node = resource("", CASES[0][1], CASES[0][3])
    assert not strong_keys(node)


def test_legitimate_cross_account_trust_keeps_separate_owners():
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.types import RelationshipType

    graph = UnifiedGraph()
    for node_id, account in (("source", "123456789012"), ("target", "987654321098")):
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.ROLE,
                label=node_id,
                attributes={
                    "cloud_provider": "aws",
                    "account_id": account,
                    "arn": f"arn:aws:iam::{account}:role/demo",
                },
            )
        )
    graph.add_edge(
        UnifiedEdge(
            source="source",
            target="target",
            relationship=RelationshipType.TRUSTS,
            evidence={"source": "cloud-inventory", "tier": "static_scan", "policy_statement": "explicit trust"},
        )
    )
    canonicalize_assets(graph)
    assert len(graph.nodes) == 2
    assert next(iter(graph.edges)).traversable


def test_raw_item_account_disagreement_survives_projection():
    from agent_bom.graph.builder import build_unified_graph_from_report

    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": {
                "provider": "aws",
                "account_id": "123456789012",
                "region": "us-east-1",
                "status": "ok",
                "instances": [{"instance_id": "i-0123456789abcdef0", "account_id": "987654321098", "name": "vm"}],
            }
        }
    )
    node = next(node for node in graph.nodes.values() if node.attributes.get("resource_type") == "instance")
    assert node.attributes["identity_scope"]["status"] == "conflict"
    assert not strong_keys(node)
    assert all(not edge.traversable for edge in graph.edges if node.id in (edge.source, edge.target))


def test_provider_dimension_conflict_cannot_bypass_exact_scope_with_native_arn():
    from agent_bom.graph.node import NodeDimensions

    node = resource("aws", CASES[0][1], CASES[0][2])
    node.dimensions = NodeDimensions(cloud_provider="azure")
    assert not strong_keys(node)


def test_declared_provider_must_agree_with_native_resource_identifier():
    node = resource("azure", CASES[0][1], CASES[0][2])
    assert not strong_keys(node)


@pytest.mark.parametrize("disk_backed", [False, True])
def test_correlating_legacy_snapshots_rechecks_scope_before_traversal(disk_backed):
    from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
    from agent_bom.graph.correlation_workspace import CorrelationMergeWorkspace
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.types import RelationshipType

    snapshots = []
    for scan in ("first", "second"):
        graph = UnifiedGraph(tenant_id="tenant", scan_id=scan, created_at="2026-10-01T00:00:00Z")
        graph.add_node(resource("aws", CASES[0][1], CASES[0][3]))
        graph.add_node(UnifiedNode(id="caller", entity_type=EntityType.ROLE, label="caller"))
        graph.add_edge(UnifiedEdge(source="caller", target="asset", relationship=RelationshipType.CAN_ACCESS))
        snapshots.append(CorrelationSnapshot.from_graph(graph))
    if disk_backed:
        with CorrelationMergeWorkspace(
            correlation_id="merged", tenant_id="tenant", created_at="2026-10-01T01:00:00Z", max_output_nodes=20, max_output_edges=20
        ) as workspace:
            for snapshot in snapshots:
                workspace.add_snapshot(snapshot)
            merged = workspace.finish()
    else:
        merged = merge_graph_snapshots(correlation_id="merged", tenant_id="tenant", snapshots=snapshots)
    assert len(merged.graph.nodes) == 4
    assert len(merged.graph.edges) == 2
    assert all(not edge.traversable and edge.evidence["identity_scope_status"] == "conflict" for edge in merged.graph.edges)
    assert all(edge.traversable for snapshot in snapshots for edge in snapshot.graph.edges), "immutable source snapshots were modified"
