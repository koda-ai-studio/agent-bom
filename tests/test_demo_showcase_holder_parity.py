"""Every holder a demo finding names is drawn in the showcase graph, linked to its package.

The bundled inventory (``agent_bom.demo``) puts PyYAML in two servers used by
two agents; the hand-built graph used to draw one server per package, so the
finding named a server and an agent the graph did not link and
``/v1/graph/impact`` on the package returned half its holders.
"""

from __future__ import annotations

import pytest

from agent_bom.demo import DEMO_INVENTORY
from agent_bom.demo_estate.showcase_graph import build_showcase_graph
from agent_bom.demo_estate.showcase_ids import showcase_agent_id, showcase_server_id
from agent_bom.graph.types import RelationshipType
from agent_bom.package_utils import canonical_package_key


@pytest.fixture(scope="module")
def graph():
    built, _, _ = build_showcase_graph(profile="current")
    return built


@pytest.fixture(scope="module")
def local_rows():
    from agent_bom.demo_estate.bootstrap import _run_demo_scan_report

    report = _run_demo_scan_report(tenant_id="default")
    rows = [row for row in report["blast_radius"] if row.get("affected_servers")]
    assert len(rows) == 15
    return rows


def _pairs(graph) -> set[tuple[str, str, RelationshipType]]:
    return {(edge.source, edge.target, edge.relationship) for edge in graph.edges}


def test_every_named_holder_exists_and_is_linked_to_the_package(graph, local_rows) -> None:
    pairs = _pairs(graph)
    multi_holder = 0
    for row in local_rows:
        package = f"pkg:{canonical_package_key(row['package_name'], row['package_version'], row['ecosystem'])}"
        assert package in graph.nodes, package
        servers = [showcase_server_id(name) for name in row["affected_servers"]]
        for server in servers:
            assert server in graph.nodes, (row["package"], server)
            assert (server, package, RelationshipType.DEPENDS_ON) in pairs, (row["package"], server)
        for agent in row["affected_agents"]:
            assert showcase_agent_id(agent) in graph.nodes, (row["package"], agent)
            assert any((showcase_agent_id(agent), server, RelationshipType.USES) in pairs for server in servers), (row["package"], agent)
        multi_holder += len(servers) > 1
    assert multi_holder >= 6, "pyyaml, requests, cryptography, axios, node-fetch and jinja2 each have several holders"


def test_package_impact_returns_every_recorded_holder(graph) -> None:
    affected = set(graph.impact_of("pkg:pypi:pyyaml@5.3", max_depth=4)["affected_nodes"])
    assert {
        showcase_server_id("shell-runner-server"),
        showcase_server_id("warehouse-server"),
        showcase_agent_id("cursor"),
        showcase_agent_id("data-pipeline"),
    } <= affected


def test_graph_draws_exactly_the_inventory_holders(graph) -> None:
    """No holder beyond what the inventory records: the graph follows the inventory, both ways."""
    recorded = {
        (showcase_server_id(server["name"]), f"pkg:{canonical_package_key(pkg['name'], pkg['version'], pkg['ecosystem'])}")
        for agent in DEMO_INVENTORY["agents"]
        for server in agent["mcp_servers"]
        for pkg in server["packages"]
    }
    drawn = {
        (edge.source, edge.target)
        for edge in graph.edges
        if edge.relationship is RelationshipType.DEPENDS_ON and edge.source.startswith("server:") and edge.target.startswith("pkg:")
    }
    assert drawn == recorded
