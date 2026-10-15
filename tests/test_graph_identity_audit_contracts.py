"""Graph identity contracts: conflicts stay split, aliases stay per snapshot, ids keep case."""

from copy import deepcopy

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.trace_inventory_correlation import correlate_inventory_observations
from agent_bom.graph.asset_canonicalize import canonicalize_assets
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.correlation_workspace import CorrelationMergeWorkspace
from agent_bom.graph.credential_reach import credential_routes
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType

ARM = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def node(identifier, **attrs):
    return UnifiedNode(
        id=identifier,
        entity_type=EntityType.CLOUD_RESOURCE,
        label=identifier,
        attributes=attrs,
        dimensions=NodeDimensions(cloud_provider="azure", environment="prod"),
    )


def merge(*graphs):
    return merge_graph_snapshots(correlation_id="audit", tenant_id="t", snapshots=[CorrelationSnapshot.from_graph(g) for g in graphs]).graph


def merge_on_disk(*graphs):
    with CorrelationMergeWorkspace(
        correlation_id="audit", tenant_id="t", created_at="2026-10-14T00:00:00+00:00", max_output_nodes=100, max_output_edges=100
    ) as workspace:
        for g in graphs:
            workspace.add_snapshot(CorrelationSnapshot.from_graph(g))
        return workspace.finish()


MERGES = pytest.mark.parametrize("merge_path", ["memory", "workspace"])


def merged(merge_path, *graphs):
    return merge(*graphs) if merge_path == "memory" else merge_on_disk(*graphs).graph


def test_conflicting_vm_generations_stay_separate_within_build():
    g = UnifiedGraph()
    for identifier, vm in [("a1", "vm-1"), ("a2", "vm-1"), ("b1", "vm-2"), ("b2", "vm-2")]:
        g.add_node(node(identifier, cloud_provider="azure", resource_id=ARM, vm_id=vm))
    canonicalize_assets(g)
    assert len(g.nodes) == 2


@MERGES
def test_conflicting_vm_generations_stay_separate_across_snapshots(merge_path):
    a, b = UnifiedGraph(tenant_id="t", scan_id="a"), UnifiedGraph(tenant_id="t", scan_id="b")
    a.add_node(node("a", cloud_provider="azure", resource_id=ARM, vm_id="vm-1"))
    b.add_node(node("b", cloud_provider="azure", resource_id=ARM, vm_id="vm-2"))
    assert len(merged(merge_path, a, b).nodes) == 2
    assert merge_on_disk(a, b).manifest["output"]["strong_key_conflict_count"] == 1


def test_new_snapshot_cannot_change_old_snapshot_alias_binding(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")

    def snapshot(scan, target):
        g = UnifiedGraph(tenant_id="t", scan_id=scan)
        for identifier in ["asset-a", "asset-b"]:
            attrs = {"cloud_provider": "azure", "account_id": "sub"}
            if identifier == target:
                attrs["identity"] = {"aliases": ["source:vm"]}
            g.add_node(node(identifier, **attrs))
        return g

    obs = {
        "observation_id": "o",
        "tenant_id": "t",
        "surface": "imported_trace",
        "metadata": {"inventory_node_id": "source:vm", "cloud_provider": "azure", "account_id": "sub", "environment": "prod"},
    }

    def correlate():
        return correlate_inventory_observations(store, tenant_id="t", scan_id="old", observations=[obs])["o"]

    store.save_graph(snapshot("old", "asset-a"))
    before = correlate()
    assert before["node_id"] == "asset-a"
    store.save_graph(snapshot("new", "asset-b"))
    after = correlate()
    assert after["snapshot_generation"] == before["snapshot_generation"]
    assert after["node_id"] == before["node_id"]


def test_correlation_preserves_both_credential_owners():
    graphs = []
    for day, owner in enumerate(["owner-a", "owner-b"], 1):
        g = build_unified_graph_from_report(
            {
                "agents": [
                    {
                        "name": owner,
                        "type": "custom",
                        "source": "local",
                        "mcp_servers": [
                            {
                                "name": "docs",
                                "url": "https://mcp.example.test/sse",
                                "transport": "sse",
                                "credential_env_vars": ["DOCS_TOKEN"],
                            }
                        ],
                    }
                ]
            },
            tenant_id="t",
            scan_id=owner,
        )
        g.created_at = f"2026-10-{day:02d}T00:00:00+00:00"
        assert credential_routes(g, [f"agent:{owner}"], analyzer="audit")[f"agent:{owner}"]
        graphs.append(g)
    routes = credential_routes(merge(*graphs), ["agent:owner-a", "agent:owner-b"], analyzer="audit")
    assert all(routes.values())


@pytest.mark.parametrize("transport", ["sse", "stdio"])
def test_case_sensitive_mcp_paths_are_distinct(transport):
    servers = []
    for name, segment in [("upper", "TeamA"), ("lower", "teama")]:
        server = {"name": name, "transport": transport}
        if transport == "sse":
            server["url"] = f"https://mcp.example.test/{segment}"
        else:
            server.update(command="node", args=[f"/srv/{segment}/server.js"])
        servers.append(server)
    g = build_unified_graph_from_report(
        {"agents": [{"name": "operator", "type": "custom", "source_id": "linux-host", "mcp_servers": servers}]}
    )
    assert len(g.nodes_by_type(EntityType.SERVER)) == 2


@MERGES
def test_kubernetes_uid_dedup_is_consistent_across_snapshots(merge_path):
    a, b = UnifiedGraph(tenant_id="t", scan_id="a"), UnifiedGraph(tenant_id="t", scan_id="b")
    together = UnifiedGraph()
    for g, identifier in [(a, "inventory-pod"), (b, "runtime-pod")]:
        n = UnifiedNode(
            id=identifier,
            entity_type=EntityType.CONTAINER,
            label="same-pod",
            attributes={
                "kubernetes_uid": "11111111-2222-3333-4444-555555555555",
                "cluster": "prod-cluster",
                "namespace": "apps",
                "kubernetes_kind": "Pod",
                "kubernetes_name": "api",
            },
        )
        g.add_node(n)
        together.add_node(deepcopy(n))
    canonicalize_assets(together)
    assert len(together.nodes) == 1
    assert len(merged(merge_path, a, b).nodes) == 1
