"""Every showcase server exposes, in the graph, the credentials its scanned config holds.

The agent page counts a blast radius's credentials from the scanned server env;
the exploit story counts the credential nodes the graph links to that server. A
graph seed that carries only some of them makes one agent read "2 credentials
exposed" on one page and "Credentials · 1" on the next.
"""

from __future__ import annotations

from agent_bom.demo import DEMO_INVENTORY
from agent_bom.demo_estate.showcase_constants import SHOWCASE_SERVERS
from agent_bom.demo_estate.showcase_graph import build_showcase_graph
from agent_bom.demo_estate.showcase_ids import showcase_server_id
from agent_bom.graph.types import RelationshipType


def test_graph_credentials_match_the_scanned_server_env():
    graph, _identities, _drift = build_showcase_graph(tenant_id="tenant-a", scan_id="creds", profile="current")
    for agent in DEMO_INVENTORY["agents"]:
        for server in agent["mcp_servers"]:
            if server["name"] not in SHOWCASE_SERVERS:
                continue
            expected = sorted((server.get("env") or {}).keys())
            linked = sorted(
                graph.nodes[edge.target].label
                for edge in graph.edges
                if edge.source == showcase_server_id(server["name"]) and edge.relationship == RelationshipType.EXPOSES_CRED
            )
            assert linked == expected, server["name"]
