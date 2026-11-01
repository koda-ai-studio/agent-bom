"""Every demo agent records what it is, where it runs and which platform it rides, with fake identifiers only.

The hero path read "Agent kind not recorded · Host not recorded" because no
showcase or estate agent had an ``agent_type`` attribute or a ``hosted_on``
edge; only ``platform_for`` and ``serves_model`` were drawn.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.demo_estate.estate_mcp_hosting import PLACEMENT_SOURCE
from agent_bom.demo_estate.showcase_constants import SHOWCASE_AGENTS
from agent_bom.demo_estate.showcase_graph import build_showcase_graph
from agent_bom.demo_estate.showcase_ids import showcase_agent_id
from agent_bom.graph.agent_context import agent_context
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import RelationshipType


@pytest.fixture(scope="module")
def estate():
    return build_demo_estate(tenant_id="default")


@pytest.fixture(scope="module")
def estate_graph(estate):
    built = UnifiedGraph(scan_id="estate-agent-context", tenant_id="default")
    project_estate_into_graph(built, estate, findings=build_estate_findings(estate))
    return built


def test_every_showcase_agent_has_kind_host_and_platform() -> None:
    graph, _, _ = build_showcase_graph(profile="current")
    for key in SHOWCASE_AGENTS:
        node = graph.nodes[showcase_agent_id(key)]
        context = agent_context(graph, node)
        assert context["agent_kind"] != "unknown", key
        assert context["execution"]["status"] == "recorded", key
        assert context["platforms"]["status"] == "recorded", key
        hosts = [graph.nodes[edge.target] for edge in graph.edges_from(node.id) if edge.relationship == RelationshipType.HOSTED_ON]
        assert hosts, key
        for host in hosts:
            assert host.id.startswith("cloud:") and host.attributes.get("fictional") is True, host.id


def test_every_third_party_estate_agent_runs_on_a_workload_in_its_own_cloud(estate) -> None:
    by_id = {asset.asset_id: asset for asset in estate.assets}
    agents = [a for a in estate.assets if a.resource_type == "agent" and a.tags.get("ai_lane") == "third_party"]
    assert agents
    for agent in agents:
        assert agent.tags["agent_type"], agent.asset_id
        workload = by_id[agent.tags["deployment"]]
        assert workload.resource_type == "deployment"
        assert workload.tags["host_provider"] == agent.tags["host_provider"]
        assert (workload.account_scope, workload.environment, workload.region) == (agent.account_scope, agent.environment, agent.region)
        assert agent.tags["placement_source"] == PLACEMENT_SOURCE
        assert agent.tags["synthetic"] == "true"


def test_estate_graph_agents_record_execution_and_kind(estate, estate_graph) -> None:
    third_party = {a.asset_id for a in estate.assets if a.resource_type == "agent" and a.tags.get("ai_lane") == "third_party"}
    for agent_id in third_party:
        node = estate_graph.nodes[agent_id]
        context = agent_context(estate_graph, node)
        assert context["agent_kind"] != "unknown", agent_id
        assert context["execution"]["status"] == "recorded", agent_id
