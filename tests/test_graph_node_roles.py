"""One rule names the role of a server or agent node on every surface.

The rule matches the MCP inventory rule ``/v1/agents`` applies to report
records, and the SQLite expression the inventory read uses agrees with it.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from agent_bom.domain.mcp_model import surface_counts_as_mcp_server
from agent_bom.graph.cluster_classes import classify
from agent_bom.graph.node_roles import SQLITE_ROLE_SQL, node_role

CASES = [
    ("server", {"surface": "mcp-server"}, "mcp_server"),
    ("server", {}, "mcp_server"),
    ("server", {"surface": ""}, "mcp_server"),
    ("server", {"surface": "other"}, "other_server"),
    ("server", {"surface": "filesystem"}, "other_server"),
    ("server", {"surface": "sbom"}, "other_server"),
    ("agent", {"agent_type": "claude-code"}, "agent"),
    ("agent", {}, "agent"),
    ("agent", {"agent_type": "framework-agent", "surface": "langchain"}, "framework_agent"),
    ("package", {"surface": "other"}, None),
    ("tool", {}, None),
]


@pytest.mark.parametrize(("entity_type", "dimensions", "role"), CASES)
def test_node_role(entity_type: str, dimensions: dict, role: str | None) -> None:
    assert node_role(entity_type, dimensions) == role


@pytest.mark.parametrize("surface", ["mcp-server", "", "other", "filesystem", "sbom", "container-image"])
def test_server_role_matches_the_mcp_inventory_rule(surface: str) -> None:
    is_mcp = node_role("server", {"surface": surface}) == "mcp_server"
    assert is_mcp == surface_counts_as_mcp_server(surface or None)


@pytest.mark.parametrize(("entity_type", "dimensions", "role"), CASES)
def test_sqlite_expression_agrees(entity_type: str, dimensions: dict, role: str | None) -> None:
    conn = sqlite3.connect(":memory:")
    try:
        row = conn.execute(
            f"SELECT {SQLITE_ROLE_SQL.format(alias='n')} FROM (SELECT ? AS entity_type, ? AS dimensions) n",
            (entity_type, json.dumps(dimensions)),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == role


def test_grouped_map_labels_each_role() -> None:
    assert (classify("server", role="mcp_server").key, classify("server", role="mcp_server").label) == ("type:server", "MCP servers")
    other = classify("server", role="other_server")
    assert (other.key, other.label) == ("server:other", "Other servers (not MCP)")
    assert other.tier == classify("server").tier
    framework = classify("agent", role="framework_agent")
    assert (framework.key, framework.label) == ("agent:framework", "Framework agents")
    assert classify("agent", role="agent").key == "type:agent"
    assert classify("package", ecosystem="npm").key == "package:npm"
