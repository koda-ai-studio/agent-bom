"""Estate MCP servers run on the workloads their inventory records, so agents reach CVEs.

Only one estate MCP server was ``hosted_on`` anything, so every estate CVE path
started at a workload and no estate agent chained to a vulnerability. Each
cloud-hosted server now records the deployment it runs in (a labelled synthetic
placement), and the graph draws that as ``server -[hosted_on]-> workload``.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType


@pytest.fixture(scope="module")
def estate():
    return build_demo_estate(tenant_id="default")


@pytest.fixture(scope="module")
def graph(estate):
    built = UnifiedGraph(scan_id="estate-mcp-hosting", tenant_id="default")
    project_estate_into_graph(built, estate, findings=build_estate_findings(estate))
    return built


def _servers(estate):
    return [a for a in estate.assets if a.resource_type == "server" and a.tags.get("ai_lane") == "third_party"]


def test_recorded_deployment_is_a_workload_in_the_servers_own_account(estate) -> None:
    by_id = {a.asset_id: a for a in estate.assets}
    placed = [s for s in _servers(estate) if s.tags.get("deployment")]
    assert placed
    for server in placed:
        workload = by_id[server.tags["deployment"]]
        assert workload.resource_type == "deployment"
        assert (workload.account_scope, workload.environment, workload.region) == (server.account_scope, server.environment, server.region)
        assert workload.tags["host_provider"] == server.tags["host_provider"]
        assert server.tags["placement_source"] == "synthetic-demo-placement"


def test_a_servers_tools_live_where_the_server_runs(estate) -> None:
    servers = {s.asset_id: s for s in _servers(estate)}
    for tool in (a for a in estate.assets if a.resource_type == "tool" and a.tags.get("mcp_server") in servers):
        server = servers[tool.tags["mcp_server"]]
        assert (tool.account_scope, tool.environment, tool.region) == (server.account_scope, server.environment, server.region)


def test_servers_without_a_container_host_are_not_given_one(estate) -> None:
    for server in _servers(estate):
        if server.tags.get("host_provider") not in {"aws", "azure", "gcp"}:
            assert "deployment" not in server.tags


def test_most_estate_servers_are_hosted_on_their_workload(estate, graph) -> None:
    servers = [a for a in estate.assets if a.resource_type == "server"]
    hosted = {
        e.source
        for e in graph.edges
        if e.relationship is RelationshipType.HOSTED_ON and graph.nodes[e.target].entity_type is EntityType.CONTAINER
    }
    linked = [s for s in servers if s.asset_id in hosted]
    assert len(linked) * 2 > len(servers), (len(linked), len(servers))
    for server in _servers(estate):
        if server.tags.get("deployment"):
            assert server.asset_id in hosted


def test_estate_agents_chain_through_server_workload_and_image_to_a_cve() -> None:
    from agent_bom.demo_estate import showcase_graph as sg

    identities = sg.build_demo_identity_store("default")
    snapshot, identity_store, drift_store = sg.build_showcase_graph(
        tenant_id="default", scan_id="showcase", profile="current", identity_store=identities
    )
    sg.apply_showcase_overlays(snapshot, tenant_id="default", identity_store=identity_store, drift_store=drift_store)
    sg.finalize_showcase_snapshot(snapshot, profile="current")
    sg.project_estate_onto_showcase(snapshot, tenant_id="default", profile="current")
    sg._materialize_showcase_attack_paths(snapshot)

    def kinds(path):
        return [snapshot.nodes[hop].entity_type for hop in path.hops if hop in snapshot.nodes]

    chained = []
    for path in snapshot.attack_paths:
        hop_kinds = kinds(path)
        if not hop_kinds or hop_kinds[0] is not EntityType.AGENT or hop_kinds[-1] is not EntityType.VULNERABILITY:
            continue
        if not any(":image:" in hop for hop in path.hops):
            continue
        assert hop_kinds[:5] == [EntityType.AGENT, EntityType.SERVER, EntityType.CONTAINER, EntityType.CONTAINER, EntityType.PACKAGE]
        chained.append(path)
    assert len(chained) > 50, len(chained)
